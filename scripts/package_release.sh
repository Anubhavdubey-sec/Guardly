#!/usr/bin/env bash
# PhishGuard Enterprise Release Packaging Shell Script
set -e

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    echo "CRITICAL SECURITY ERROR: '.env' is currently tracked by git!"
    echo "Run 'git rm --cached .env' before packaging for distribution."
    exit 1
fi

mkdir -p dist
OUTPUT_ZIP="dist/Phishing-Email-Detector.zip"

echo "[*] Creating release archive using git archive..."
git archive --format=zip --output="$OUTPUT_ZIP" HEAD

echo "[+] Release archive created successfully at: $OUTPUT_ZIP"
echo "[*] Inspecting release archive contents:"
unzip -l "$OUTPUT_ZIP"
