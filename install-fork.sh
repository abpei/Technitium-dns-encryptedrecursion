#!/bin/bash
# Install or update the PIDOH Encrypted-Recursion Technitium DNS fork.
# Usage: install-fork.sh [--dev|--master]
# Default: --dev
set -euo pipefail

REPO="abpei/Technitium-dns-encryptedrecursion"
INSTALL_DIR="/opt/technitium/dns"
SERVICE_NAME="dns.service"

# Parse arguments
BRANCH="dev"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev) BRANCH="dev"; shift ;;
        --master) BRANCH="master"; shift ;;
        -h|--help)
            echo "Usage: $0 [--dev|--master]"
            echo "  --dev     Install latest dev release (default)"
            echo "  --master  Install latest master release"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== PIDOH Fork Installer ==="
echo "Branch: $BRANCH"
echo ""

# Fetch latest release for the branch
echo "Fetching latest release..."
if [[ "$BRANCH" == "dev" ]]; then
    # Dev releases are tagged as v15.4.0-devN
    RELEASE_JSON=$(curl -sf "https://api.github.com/repos/${REPO}/releases?per_page=10" | \
        python3 -c "
import json, sys
releases = json.load(sys.stdin)
for r in releases:
    if r['tag_name'].startswith('v') and '-dev' in r['tag_name'] and not r['prerelease']:
        print(r['tag_name'])
        print(r['assets'][0]['browser_download_url'] if r['assets'] else '')
        break
else:
    print('NONE')
    print('')
" 2>/dev/null)
else
    # Master releases are tagged as vN.N.N without -dev suffix
    RELEASE_JSON=$(curl -sf "https://api.github.com/repos/${REPO}/releases?per_page=10" | \
        python3 -c "
import json, sys
releases = json.load(sys.stdin)
for r in releases:
    if r['tag_name'].startswith('v') and '-dev' not in r['tag_name'] and not r['prerelease']:
        print(r['tag_name'])
        print(r['assets'][0]['browser_download_url'] if r['assets'] else '')
        break
else:
    print('NONE')
    print('')
" 2>/dev/null)
fi

TAG=$(echo "$RELEASE_JSON" | head -1)
DOWNLOAD_URL=$(echo "$RELEASE_JSON" | tail -1)

if [[ "$TAG" == "NONE" || -z "$DOWNLOAD_URL" ]]; then
    echo "ERROR: No release found for branch '$BRANCH'"
    exit 1
fi

echo "Latest release: $TAG"
echo "Download URL: $DOWNLOAD_URL"
echo ""

# Check current installed version
if [[ -f "${INSTALL_DIR}/fork.json" ]]; then
    CURRENT=$(cat "${INSTALL_DIR}/fork.json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('forkVersion','unknown'))" 2>/dev/null || echo "unknown")
    echo "Currently installed: $CURRENT"
    if [[ "$CURRENT" == "$TAG" ]]; then
        echo "Already up to date."
        exit 0
    fi
    echo ""
fi

# Download
TMPDIR=$(mktemp -d)
TARBALL="${TMPDIR}/DnsServerPortable.tar.gz"
echo "Downloading..."
curl -fSL -o "$TARBALL" "$DOWNLOAD_URL"

# Verify
FILE_TYPE=$(file "$TARBALL")
if [[ "$FILE_TYPE" != *"gzip compressed"* ]]; then
    echo "ERROR: Downloaded file is not a gzip archive"
    echo "File type: $FILE_TYPE"
    rm -rf "$TMPDIR"
    exit 1
fi

echo "Download verified ($(du -h "$TARBALL" | cut -f1))"
echo ""

# Stop service
echo "Stopping ${SERVICE_NAME}..."
systemctl stop "$SERVICE_NAME"

# Extract
echo "Extracting to ${INSTALL_DIR}..."
tar -xzf "$TARBALL" -C "$INSTALL_DIR"

# Verify fork.json
if [[ -f "${INSTALL_DIR}/fork.json" ]]; then
    echo "fork.json deployed:"
    cat "${INSTALL_DIR}/fork.json"
else
    echo "WARNING: fork.json not found in deployment"
fi
echo ""

# Start service
echo "Starting ${SERVICE_NAME}..."
systemctl start "$SERVICE_NAME"

# Verify
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "=== Installation complete ==="
    # Show version from log
    journalctl -u "$SERVICE_NAME" --since "5 seconds ago" --no-pager -o cat 2>/dev/null | grep -i "started\|version" || true
else
    echo ""
    echo "ERROR: Service failed to start"
    journalctl -u "$SERVICE_NAME" --since "10 seconds ago" --no-pager | tail -10
    rm -rf "$TMPDIR"
    exit 1
fi

# Cleanup
rm -rf "$TMPDIR"

echo ""
echo "Web console: http://$(hostname -I | awk '{print $1}'):5380/"
echo "About page should show the fork version label."
