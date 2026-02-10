#!/bin/bash
# SecureVault Native Messaging Host Installer
# This script sets up the native messaging host for Chrome

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_NAME="com.securevault.app"

# Determine OS and set paths
case "$(uname -s)" in
  Linux*)
    CHROME_NATIVE_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    CHROMIUM_NATIVE_DIR="$HOME/.config/chromium/NativeMessagingHosts"
    ;;
  Darwin*)
    CHROME_NATIVE_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    CHROMIUM_NATIVE_DIR="$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
    ;;
  MINGW*|CYGWIN*|MSYS*)
    echo "For Windows, please run install-host.bat instead"
    exit 1
    ;;
  *)
    echo "Unsupported OS"
    exit 1
    ;;
esac

echo "================================================"
echo "  SecureVault Native Messaging Host Installer"
echo "================================================"
echo ""

# Get extension ID
read -p "Enter your Chrome extension ID: " EXTENSION_ID

if [ -z "$EXTENSION_ID" ]; then
  echo "Error: Extension ID is required"
  exit 1
fi

# Create host manifest
HOST_MANIFEST='{
  "name": "'"$HOST_NAME"'",
  "description": "SecureVault Password Manager",
  "path": "'"$SCRIPT_DIR/securevault-native-host"'",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://'"$EXTENSION_ID"'/"
  ]
}'

# Install for Chrome
if [ -d "$(dirname "$CHROME_NATIVE_DIR")" ]; then
  mkdir -p "$CHROME_NATIVE_DIR"
  echo "$HOST_MANIFEST" > "$CHROME_NATIVE_DIR/$HOST_NAME.json"
  echo "✓ Installed for Google Chrome"
fi

# Install for Chromium
if [ -d "$(dirname "$CHROMIUM_NATIVE_DIR")" ]; then
  mkdir -p "$CHROMIUM_NATIVE_DIR"
  echo "$HOST_MANIFEST" > "$CHROMIUM_NATIVE_DIR/$HOST_NAME.json"
  echo "✓ Installed for Chromium"
fi

echo ""
echo "Installation complete!"
echo "Restart your browser for changes to take effect."
