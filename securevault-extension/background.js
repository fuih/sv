/**
 * SecureVault - Background Service Worker
 * Handles native messaging with the desktop app
 */

const NATIVE_HOST_NAME = "com.securevault.app";

// Connection state
let nativePort = null;
let isConnected = false;
let pendingRequests = new Map();
let requestId = 0;

/**
 * Connect to the native messaging host (desktop app)
 */
function connectToNativeHost() {
    try {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
        isConnected = true;

        nativePort.onMessage.addListener((message) => {
            handleNativeMessage(message);
        });

        nativePort.onDisconnect.addListener(() => {
            isConnected = false;
            nativePort = null;
            console.log("Disconnected from SecureVault desktop app");

            // Reject all pending requests
            pendingRequests.forEach((resolve, id) => {
                resolve({ success: false, error: "Disconnected from desktop app" });
            });
            pendingRequests.clear();
        });

        console.log("Connected to SecureVault desktop app");
        return true;
    } catch (err) {
        console.error("Failed to connect to native host:", err);
        isConnected = false;
        return false;
    }
}

/**
 * Send a message to the native host and get a response
 */
function sendNativeMessage(action, data = {}) {
    return new Promise((resolve) => {
        if (!isConnected) {
            if (!connectToNativeHost()) {
                resolve({
                    success: false,
                    error: "Cannot connect to SecureVault. Is the app running?",
                });
                return;
            }
        }

        const id = ++requestId;
        const message = { id, action, ...data };

        pendingRequests.set(id, resolve);

        // Timeout after 10 seconds
        setTimeout(() => {
            if (pendingRequests.has(id)) {
                pendingRequests.delete(id);
                resolve({ success: false, error: "Request timed out" });
            }
        }, 10000);

        try {
            nativePort.postMessage(message);
        } catch (err) {
            pendingRequests.delete(id);
            resolve({ success: false, error: "Failed to send message" });
        }
    });
}

/**
 * Handle messages from the native host
 */
function handleNativeMessage(message) {
    if (message.id && pendingRequests.has(message.id)) {
        pendingRequests.get(message.id)(message);
        pendingRequests.delete(message.id);
    }
}

/**
 * Handle messages from content scripts and popup
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        switch (request.action) {
            case "getPasswords":
                const passwords = await sendNativeMessage("get_passwords_for_url", {
                    url: request.url,
                });
                sendResponse(passwords);
                break;

            case "getAllPasswords":
                const allPasswords = await sendNativeMessage("get_passwords");
                sendResponse(allPasswords);
                break;

            case "generatePassword":
                const generated = await sendNativeMessage("generate_password", {
                    length: request.length || 24,
                    lowercase: true,
                    uppercase: true,
                    digits: true,
                    special: true,
                    exclude_ambiguous: true,
                });
                sendResponse(generated);
                break;

            case "savePassword":
                const saved = await sendNativeMessage("add_password", {
                    site_name: request.siteName,
                    site_url: request.siteUrl,
                    username: request.username,
                    password: request.password,
                    notes: "",
                });
                sendResponse(saved);
                break;

            case "checkConnection":
                sendResponse({ success: isConnected });
                break;

            case "connect":
                const connected = connectToNativeHost();
                sendResponse({ success: connected });
                break;

            default:
                sendResponse({ success: false, error: "Unknown action" });
        }
    })();

    return true; // Keep the message channel open for async response
});

// Update badge based on connection status
function updateBadge() {
    if (isConnected) {
        chrome.action.setBadgeText({ text: "" });
    } else {
        chrome.action.setBadgeText({ text: "!" });
        chrome.action.setBadgeBackgroundColor({ color: "#f85149" });
    }
}

// Periodic connection check
setInterval(() => {
    updateBadge();
}, 5000);
