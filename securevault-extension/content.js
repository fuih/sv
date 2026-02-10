/**
 * SecureVault - Content Script
 * Detects password fields and provides autofill/generation UI
 */

(function () {
    "use strict";

    // Avoid running multiple times
    if (window.__securevault_injected) return;
    window.__securevault_injected = true;

    const OVERLAY_ID = "securevault-overlay";
    let currentField = null;
    let overlay = null;

    /**
     * Detect if a form is a login or signup form
     */
    function detectFormType(passwordField) {
        const form = passwordField.closest("form");
        const pageText = document.body.innerText.toLowerCase();
        const formHTML = form ? form.innerHTML.toLowerCase() : "";
        const actionUrl = form ? (form.action || "").toLowerCase() : "";

        // Signup indicators
        const signupKeywords = [
            "sign up",
            "signup",
            "register",
            "create account",
            "join",
            "new account",
            "confirm password",
            "repeat password",
            "retype password",
        ];

        // Count password fields in the form
        const passwordFields = form
            ? form.querySelectorAll('input[type="password"]')
            : document.querySelectorAll('input[type="password"]');

        const hasMultiplePasswordFields = passwordFields.length > 1;

        // Check for signup indicators
        const isSignup =
            hasMultiplePasswordFields ||
            signupKeywords.some(
                (kw) =>
                    formHTML.includes(kw) ||
                    actionUrl.includes(kw.replace(" ", "")) ||
                    pageText.includes(kw)
            );

        return isSignup ? "signup" : "login";
    }

    /**
     * Create the autofill overlay
     */
    function createOverlay(field, formType) {
        removeOverlay();

        overlay = document.createElement("div");
        overlay.id = OVERLAY_ID;
        overlay.className = "securevault-overlay";

        const rect = field.getBoundingClientRect();
        overlay.style.position = "fixed";
        overlay.style.left = `${rect.left}px`;
        overlay.style.top = `${rect.bottom + 4}px`;
        overlay.style.zIndex = "2147483647";
        overlay.style.width = `${Math.max(rect.width, 300)}px`;

        if (formType === "login") {
            overlay.innerHTML = createLoginOverlay();
            document.body.appendChild(overlay);
            loadSavedPasswords(field);
        } else {
            overlay.innerHTML = createSignupOverlay();
            document.body.appendChild(overlay);
            generateNewPassword();
        }

        // Close when clicking outside
        document.addEventListener("click", handleOutsideClick);
    }

    /**
     * Create login overlay HTML
     */
    function createLoginOverlay() {
        return `
      <div class="sv-overlay-container">
        <div class="sv-header">
          <span class="sv-logo">🔐</span>
          <span class="sv-title">SecureVault</span>
        </div>
        <div class="sv-content" id="sv-content">
          <div class="sv-loading">
            <div class="sv-spinner"></div>
            <span>Loading passwords...</span>
          </div>
        </div>
      </div>
    `;
    }

    /**
     * Create signup overlay HTML
     */
    function createSignupOverlay() {
        return `
      <div class="sv-overlay-container">
        <div class="sv-header">
          <span class="sv-logo">🔐</span>
          <span class="sv-title">SecureVault</span>
          <span class="sv-badge">New Account</span>
        </div>
        <div class="sv-content" id="sv-content">
          <div class="sv-loading">
            <div class="sv-spinner"></div>
            <span>Generating secure password...</span>
          </div>
        </div>
      </div>
    `;
    }

    /**
     * Load saved passwords for the current site
     */
    function loadSavedPasswords(field) {
        const url = window.location.href;

        chrome.runtime.sendMessage(
            { action: "getPasswords", url },
            (response) => {
                const content = document.getElementById("sv-content");
                if (!content) return;

                if (chrome.runtime.lastError || !response || !response.success) {
                    content.innerHTML = `
            <div class="sv-empty">
              <p>Could not connect to SecureVault</p>
              <p class="sv-hint">Make sure the desktop app is running</p>
            </div>
          `;
                    return;
                }

                const passwords = response.data || [];

                if (passwords.length === 0) {
                    content.innerHTML = `
            <div class="sv-empty">
              <p>No passwords saved for this site</p>
              <p class="sv-hint">Add one in the SecureVault app</p>
            </div>
          `;
                    return;
                }

                content.innerHTML = passwords
                    .map(
                        (entry, i) => `
          <div class="sv-entry" data-index="${i}">
            <div class="sv-entry-icon">${entry.site_name.charAt(0).toUpperCase()}</div>
            <div class="sv-entry-info">
              <div class="sv-entry-username">${escapeHtml(entry.username)}</div>
              <div class="sv-entry-site">${escapeHtml(entry.site_name)}</div>
            </div>
          </div>
        `
                    )
                    .join("");

                // Add click handlers
                content.querySelectorAll(".sv-entry").forEach((el, i) => {
                    el.addEventListener("click", () => {
                        const entry = passwords[i];
                        fillCredentials(field, entry);
                        removeOverlay();
                    });
                });
            }
        );
    }

    /**
     * Generate a new password for signup
     */
    function generateNewPassword() {
        chrome.runtime.sendMessage(
            { action: "generatePassword", length: 24 },
            (response) => {
                const content = document.getElementById("sv-content");
                if (!content) return;

                if (chrome.runtime.lastError || !response || !response.success) {
                    content.innerHTML = `
            <div class="sv-empty">
              <p>Could not connect to SecureVault</p>
              <p class="sv-hint">Make sure the desktop app is running</p>
            </div>
          `;
                    return;
                }

                const generated = response.data;
                content.innerHTML = `
          <div class="sv-generated">
            <div class="sv-password-preview">${escapeHtml(generated.password)}</div>
            <div class="sv-strength">
              <div class="sv-strength-bar">
                <div class="sv-strength-fill sv-${generated.strength.toLowerCase()}" style="width:100%"></div>
              </div>
              <span class="sv-strength-label">${generated.strength}</span>
            </div>
            <div class="sv-actions">
              <button class="sv-btn sv-btn-primary" id="sv-use-password">Use This Password</button>
              <button class="sv-btn sv-btn-secondary" id="sv-regenerate">Regenerate</button>
            </div>
            <label class="sv-save-check">
              <input type="checkbox" id="sv-save-to-vault" checked>
              <span>Save to SecureVault</span>
            </label>
          </div>
        `;

                // Use password
                document.getElementById("sv-use-password").addEventListener("click", () => {
                    fillPassword(currentField, generated.password);

                    // Save to vault if checked
                    const saveCheckbox = document.getElementById("sv-save-to-vault");
                    if (saveCheckbox && saveCheckbox.checked) {
                        const form = currentField.closest("form");
                        const usernameField = findUsernameField(form);
                        const username = usernameField ? usernameField.value : "";

                        chrome.runtime.sendMessage({
                            action: "savePassword",
                            siteName: document.title || window.location.hostname,
                            siteUrl: window.location.origin,
                            username: username,
                            password: generated.password,
                        });
                    }

                    removeOverlay();
                });

                // Regenerate
                document.getElementById("sv-regenerate").addEventListener("click", () => {
                    const content = document.getElementById("sv-content");
                    if (content) {
                        content.innerHTML = `
              <div class="sv-loading">
                <div class="sv-spinner"></div>
                <span>Generating secure password...</span>
              </div>
            `;
                    }
                    generateNewPassword();
                });
            }
        );
    }

    /**
     * Fill credentials into form fields
     */
    function fillCredentials(passwordField, entry) {
        const form = passwordField.closest("form");
        const usernameField = findUsernameField(form);

        if (usernameField) {
            setFieldValue(usernameField, entry.username);
        }
        setFieldValue(passwordField, entry.password);
    }

    /**
     * Fill just the password
     */
    function fillPassword(field, password) {
        setFieldValue(field, password);

        // Also fill confirm password if it exists
        const form = field.closest("form");
        if (form) {
            const passwordFields = form.querySelectorAll('input[type="password"]');
            passwordFields.forEach((pf) => {
                setFieldValue(pf, password);
            });
        }
    }

    /**
     * Set a field's value, triggering React/Angular change events
     */
    function setFieldValue(field, value) {
        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype,
            "value"
        ).set;

        nativeInputValueSetter.call(field, value);
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
    }

    /**
     * Find the username/email field in a form
     */
    function findUsernameField(form) {
        if (!form) return null;

        const selectors = [
            'input[type="email"]',
            'input[name*="user"]',
            'input[name*="email"]',
            'input[name*="login"]',
            'input[id*="user"]',
            'input[id*="email"]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]',
            'input[type="text"]',
        ];

        for (const selector of selectors) {
            const field = form.querySelector(selector);
            if (field && field.type !== "password" && field.type !== "hidden") {
                return field;
            }
        }

        return null;
    }

    /**
     * Remove the overlay
     */
    function removeOverlay() {
        const existing = document.getElementById(OVERLAY_ID);
        if (existing) {
            existing.remove();
        }
        overlay = null;
        document.removeEventListener("click", handleOutsideClick);
    }

    /**
     * Handle clicks outside the overlay
     */
    function handleOutsideClick(e) {
        if (overlay && !overlay.contains(e.target) && e.target !== currentField) {
            removeOverlay();
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Watch for password fields
     */
    function watchPasswordFields() {
        // Initial scan
        document.querySelectorAll('input[type="password"]').forEach(attachToField);

        // Watch for dynamically added fields
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) {
                        if (node.matches && node.matches('input[type="password"]')) {
                            attachToField(node);
                        }
                        node.querySelectorAll &&
                            node
                                .querySelectorAll('input[type="password"]')
                                .forEach(attachToField);
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
        });
    }

    /**
     * Attach event listeners to a password field
     */
    function attachToField(field) {
        if (field.__securevault_attached) return;
        field.__securevault_attached = true;

        field.addEventListener("focus", () => {
            currentField = field;
            const formType = detectFormType(field);
            createOverlay(field, formType);
        });
    }

    // Start watching
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", watchPasswordFields);
    } else {
        watchPasswordFields();
    }
})();
