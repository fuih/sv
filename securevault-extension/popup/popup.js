/**
 * SecureVault Extension Popup Script
 */

document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.getElementById("search-input");
    const passwordList = document.getElementById("password-list");
    const generateBtn = document.getElementById("generate-btn");
    const openAppBtn = document.getElementById("open-app-btn");
    const connectionStatus = document.getElementById("connection-status");

    let allPasswords = [];
    let showingGenerator = false;

    // Check connection status
    checkConnection();

    // Load passwords
    loadPasswords();

    // Event listeners
    searchInput.addEventListener("input", filterPasswords);
    generateBtn.addEventListener("click", toggleGenerator);
    openAppBtn.addEventListener("click", () => {
        // The native messaging will wake up the app
        chrome.runtime.sendMessage({ action: "connect" });
    });

    /**
     * Check connection to desktop app
     */
    function checkConnection() {
        chrome.runtime.sendMessage({ action: "checkConnection" }, (response) => {
            if (chrome.runtime.lastError || !response) {
                setConnectionStatus("disconnected", "Desktop app not connected");
                return;
            }

            if (response.success) {
                setConnectionStatus("connected", "Connected to desktop app");
            } else {
                setConnectionStatus("disconnected", "Desktop app not running");
            }
        });
    }

    /**
     * Set connection status UI
     */
    function setConnectionStatus(status, text) {
        connectionStatus.className = `status-bar status-${status}`;
        connectionStatus.querySelector(".status-text").textContent = text;
    }

    /**
     * Load all passwords
     */
    function loadPasswords() {
        chrome.runtime.sendMessage({ action: "getAllPasswords" }, (response) => {
            if (chrome.runtime.lastError || !response || !response.success) {
                passwordList.innerHTML = `
          <div class="empty-state">
            <p>Cannot connect to SecureVault</p>
            <p class="hint">Make sure the desktop app is running</p>
          </div>
        `;
                return;
            }

            allPasswords = response.data || [];
            renderPasswords(allPasswords);
        });
    }

    /**
     * Render password list
     */
    function renderPasswords(passwords) {
        if (passwords.length === 0) {
            passwordList.innerHTML = `
        <div class="empty-state">
          <p>No passwords found</p>
          <p class="hint">Add passwords via the desktop app</p>
        </div>
      `;
            return;
        }

        passwordList.innerHTML = passwords
            .map(
                (entry, i) => `
      <div class="password-item" data-index="${i}">
        <div class="item-icon">${escapeHtml(entry.site_name.charAt(0).toUpperCase())}</div>
        <div class="item-info">
          <div class="item-name">${escapeHtml(entry.site_name)}</div>
          <div class="item-username">${escapeHtml(entry.username)}</div>
        </div>
        <button class="item-copy" data-password="${escapeAttr(entry.password)}" title="Copy password">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
          </svg>
        </button>
      </div>
    `
            )
            .join("");

        // Copy handlers
        passwordList.querySelectorAll(".item-copy").forEach((btn) => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const password = btn.getAttribute("data-password");
                copyToClipboard(password);

                // Visual feedback
                btn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2" width="16" height="16">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        `;
                setTimeout(() => {
                    btn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
            </svg>
          `;
                }, 1500);
            });
        });

        // Click on item to autofill on active tab
        passwordList.querySelectorAll(".password-item").forEach((item, i) => {
            item.addEventListener("click", () => {
                const entry = passwords[i];
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        chrome.tabs.sendMessage(tabs[0].id, {
                            action: "autofill",
                            username: entry.username,
                            password: entry.password,
                        });
                        window.close();
                    }
                });
            });
        });
    }

    /**
     * Filter passwords based on search
     */
    function filterPasswords() {
        const query = searchInput.value.toLowerCase();
        if (!query) {
            renderPasswords(allPasswords);
            return;
        }

        const filtered = allPasswords.filter(
            (p) =>
                p.site_name.toLowerCase().includes(query) ||
                p.site_url.toLowerCase().includes(query) ||
                p.username.toLowerCase().includes(query)
        );
        renderPasswords(filtered);
    }

    /**
     * Toggle password generator view
     */
    function toggleGenerator() {
        if (showingGenerator) {
            showingGenerator = false;
            generateBtn.textContent = "Generate";
            renderPasswords(allPasswords);
            return;
        }

        showingGenerator = true;
        generatePassword();
    }

    /**
     * Generate a password and show it
     */
    function generatePassword() {
        passwordList.innerHTML = `
      <div class="loading"><div class="spinner"></div></div>
    `;

        chrome.runtime.sendMessage(
            { action: "generatePassword", length: 24 },
            (response) => {
                if (chrome.runtime.lastError || !response || !response.success) {
                    passwordList.innerHTML = `
            <div class="empty-state">
              <p>Cannot generate password</p>
              <p class="hint">Make sure the desktop app is running</p>
            </div>
          `;
                    return;
                }

                const generated = response.data;
                passwordList.innerHTML = `
          <div class="generated-container">
            <div class="generated-password">${escapeHtml(generated.password)}</div>
            <div class="gen-actions">
              <button class="gen-btn gen-btn-copy" id="copy-gen">Copy</button>
              <button class="gen-btn gen-btn-regen" id="regen">Regenerate</button>
            </div>
          </div>
        `;

                document.getElementById("copy-gen").addEventListener("click", () => {
                    copyToClipboard(generated.password);
                    document.getElementById("copy-gen").textContent = "Copied!";
                    setTimeout(() => {
                        const btn = document.getElementById("copy-gen");
                        if (btn) btn.textContent = "Copy";
                    }, 1500);
                });

                document.getElementById("regen").addEventListener("click", generatePassword);
            }
        );
    }

    /**
     * Copy text to clipboard
     */
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).catch(() => {
            // Fallback
            const textarea = document.createElement("textarea");
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand("copy");
            document.body.removeChild(textarea);
        });
    }

    /**
     * Escape HTML
     */
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Escape attribute value
     */
    function escapeAttr(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }
});
