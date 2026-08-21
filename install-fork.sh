#!/bin/bash
# Install or update the PIDOH Encrypted-Recursion Technitium DNS fork.
# Usage: install-fork.sh [--dev|--master] [--force]
# Default: --dev
set -euo pipefail

REPO="abpei/Technitium-dns-encryptedrecursion"
INSTALL_DIR="/opt/technitium/dns"
SERVICE_NAME="dns.service"

# Parse arguments
BRANCH="dev"
FORCE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev) BRANCH="dev"; shift ;;
        --master) BRANCH="master"; shift ;;
        --force) FORCE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--dev|--master] [--force]"
            echo "  --dev     Install latest dev release (default)"
            echo "  --master  Install latest master release"
            echo "  --force   Skip version check, reinstall even if same version"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== PIDOH Fork Installer ==="
echo "Branch: $BRANCH"
echo ""

# Fetch releases and find the most recent one matching the branch
echo "Fetching releases..."
ALL_JSON=$(curl -sf "https://api.github.com/repos/${REPO}/releases?per_page=20" 2>/dev/null || true)
RELEASE=$(echo "$ALL_JSON" | python3 -c "
import json,sys
releases=json.load(sys.stdin)
if '${BRANCH}' == 'dev':
    # Prefer new-format tags (-pidoh-dev), then old-format (-dev)
    for tag_pattern in ['-pidoh-dev', '-dev']:
        for r in releases:
            t=r.get('tag_name','')
            if tag_pattern in t:
                a=r.get('assets',[])
                print(json.dumps({'tag':t,'url':a[0]['browser_download_url'] if a else ''}))
                sys.exit(0)
else:
    # Prefer new-format tags (-pidoh.), then old-format (no -dev)
    for tag_pattern in ['-pidoh.', '-dev']:
        for r in releases:
            t=r.get('tag_name','')
            if tag_pattern == '-dev' and '-dev' in t:
                continue
            if tag_pattern == '-pidoh.' and '-pidoh.' in t:
                a=r.get('assets',[])
                print(json.dumps({'tag':t,'url':a[0]['browser_download_url'] if a else ''}))
                sys.exit(0)
        if tag_pattern == '-pidoh.':
            # Fallback: any tag without -dev
            for r in releases:
                t=r.get('tag_name','')
                if '-dev' not in t:
                    a=r.get('assets',[])
                    print(json.dumps({'tag':t,'url':a[0]['browser_download_url'] if a else ''}))
                    sys.exit(0)
" 2>/dev/null || true)
TAG=$(echo "$RELEASE" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag'])" 2>/dev/null || true)
ASSET_URL=$(echo "$RELEASE" | python3 -c "import json,sys; print(json.load(sys.stdin)['url'])" 2>/dev/null || true)

if [[ -z "$TAG" ]]; then
    echo "ERROR: No ${BRANCH} release found"
    exit 1
fi

echo "Latest release: $TAG"
echo ""

# Check current installed version
if [[ "$FORCE" == "true" ]]; then
    echo "Force mode: skipping version check"
    echo ""
elif [[ -f "${INSTALL_DIR}/fork.json" ]]; then
    CURRENT=$(python3 -c "import json; d=json.load(open('${INSTALL_DIR}/fork.json')); print(d.get('forkVersion','unknown'))" 2>/dev/null || echo "unknown")
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
if [[ -n "$ASSET_URL" ]]; then
    curl -fSL -o "$TARBALL" "$ASSET_URL"
else
    # Fallback: construct URL from tag
    curl -fSL -o "$TARBALL" "https://github.com/${REPO}/releases/download/${TAG}/DnsServerPortable.tar.gz"
fi

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
