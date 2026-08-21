# Release Process

This document describes how releases are created and distributed for the PiDoH Encrypted-Recursion fork of Technitium DNS Server.

## Triggering a Release

1. Go to the **GitHub Actions** tab in the repository
2. Select the **Release** workflow
3. Click **Run workflow**
4. Choose a branch:
   - **dev** — Creates a pre-release (beta/testing channel)
   - **master** — Creates a stable release
5. Optionally provide custom release notes (if left blank, the workflow uses the `updateMessage` from `update.json`)
6. Click **Run workflow**

## What the Workflow Does

The release workflow (`.github/workflows/release.yml`) performs these steps:

1. **Checkout** — Clones the selected branch
2. **Read version** — Parses `DnsServerApp/fork.json` to get the current `forkVersion`
3. **Bump version** — Increments the 4th digit (fork increment) in the version string
4. **Update metadata** — Writes the new version to both `fork.json` and `update.json`
5. **Commit** — Pushes the version bump to the branch
6. **Build** — Compiles with .NET 10 SDK (`dotnet publish`)
7. **Package** — Creates `DnsServerPortable.tar.gz` from the build output
8. **Release** — Creates a GitHub release with the version tag, attaches the tarball, and marks dev releases as pre-releases

## Version Convention

Format: `v<major>.<minor>.<patch>-pidoh[-dev].<forkIncrement>`

| Part | Meaning |
|------|---------|
| `v15.4.0` | Upstream Technitium DNS Server version |
| `-pidoh` | Fork identifier (PIDOH = Privacy-focused DNS) |
| `-dev` | Branch indicator (present only for dev releases) |
| `.N` | Fork increment — auto-increases with each release |

**Examples:**
- `v15.4.0-pidoh.1` — First stable release for the v15.4.0 upstream base
- `v15.4.0-pidoh-dev.16` — Sixteenth dev release for the v15.4.0 upstream base

## fork.json and update.json

### fork.json (`DnsServerApp/fork.json`)

Tracks fork metadata and is included in the release tarball:

```json
{
    "forkName": "PIDOH Encrypted-Recursion Fork",
    "forkShortName": "PiDoH",
    "forkBranch": "dev",
    "forkVersion": "v15.4.0-pidoh-dev.16",
    "upstreamVersion": "15.4.0"
}
```

| Field | Description |
|-------|-------------|
| `forkName` | Human-readable fork name |
| `forkShortName` | Short identifier used in version tags |
| `forkBranch` | Active branch (`dev` or `master`) |
| `forkVersion` | Current version tag (auto-incremented by workflow) |
| `upstreamVersion` | Base Technitium DNS Server version |

### update.json (root)

Used by the DNS server's auto-update mechanism to notify users:

```json
{
    "updateVersion": "15.4.0-pidoh-dev.16",
    "updateTitle": "PiDoH Fork v15.4.0-pidoh-dev.16 Available!",
    "updateMessage": "Fix: CNAME chain allow/block determination now checks final target only.",
    "instructionsLink": "https://github.com/abpei/Technitium-dns-encryptedrecursion/releases/tag/v15.4.0-pidoh-dev.16",
    "changeLogLink": "https://github.com/abpei/Technitium-dns-encryptedrecursion/releases/tag/v15.4.0-pidoh-dev.16"
}
```

| Field | Description |
|-------|-------------|
| `updateVersion` | Version string (without `v` prefix) |
| `updateTitle` | Shown in the update notification |
| `updateMessage` | Release notes / changelog summary |
| `instructionsLink` | URL to the release page |
| `changeLogLink` | URL to the changelog |

Both files are updated by the workflow on each release.

## How install-fork.sh Picks Releases

The `install-fork.sh` script uses the GitHub API to find and install the latest release:

1. **Fetch releases** — Queries `https://api.github.com/repos/abpei/Technitium-dns-encryptedrecursion/releases?per_page=20`
2. **Filter by branch** — Matches tags by pattern:
   - For `--dev`: Looks for tags containing `-pidoh-dev` first, then falls back to `-dev`
   - For `--master`: Looks for tags containing `-pidoh.` (without `-dev`), then falls back to any tag without `-dev`
3. **Version check** — Compares the tag against the installed `fork.json` version; skips if already current
4. **Download** — Fetches the `DnsServerPortable.tar.gz` asset from the release
5. **Install** — Stops the DNS service, extracts the tarball to `/opt/technitium/dns`, and restarts

### Usage

```bash
# Install latest dev release (default)
./install-fork.sh

# Install latest stable release
./install-fork.sh --master

# Force reinstall (skip version check)
./install-fork.sh --force
```

## Release Artifacts

Each release produces:

| Artifact | Description |
|----------|-------------|
| `DnsServerPortable.tar.gz` | Portable DNS server package (extract to install) |
| GitHub Release | Tagged release with notes and download link |
| Updated `fork.json` | Committed to the branch with the new version |
| Updated `update.json` | Committed to the branch with update metadata |
