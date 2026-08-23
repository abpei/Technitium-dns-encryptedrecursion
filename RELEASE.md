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
6. **Setup .NET SDK** — Installs .NET 10 SDK on the runner
7. **Build TechnitiumLibrary** — Clones `TechnitiumSoftware/TechnitiumLibrary` as a sibling directory and builds the 5 required projects (TechnitiumLibrary, ByteTree, IO, Security.OTP, Net) in dependency order. The Firewall project is skipped (COM reference not supported on Linux).
8. **Build** — Compiles the fork with `dotnet publish DnsServerApp/DnsServerApp.csproj -c Release`
9. **Package** — Creates `DnsServerPortable.tar.gz` from the build output
10. **Release** — Creates a GitHub release with the version tag, attaches the tarball, and marks dev releases as pre-releases

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
- `v15.4.0-pidoh-dev.29` — Latest dev release for the v15.4.0 upstream base

## fork.json and update.json

### fork.json (`DnsServerApp/fork.json`)

Tracks fork metadata and is included in the release tarball:

```json
{
    "forkName": "PIDOH Encrypted-Recursion Fork",
    "forkShortName": "PiDoH",
    "forkBranch": "dev",
    "forkVersion": "v15.4.0-pidoh-dev.29",
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
    "updateVersion": "15.4.0-pidoh-dev.29",
    "updateTitle": "PiDoH Fork v15.4.0-pidoh-dev.29 Available!",
    "updateMessage": "Domain checker now shows both blocklist and AllowedZone status with blocklist sources in ALLOWED banner.",
    "instructionsLink": "https://github.com/abpei/Technitium-dns-encryptedrecursion/releases/tag/v15.4.0-pidoh-dev.29",
    "changeLogLink": "https://github.com/abpei/Technitium-dns-encryptedrecursion/releases/tag/v15.4.0-pidoh-dev.29"
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

## Fork Features

The following fork-specific features are included in all releases:

| Feature | Description |
|---------|-------------|
| Fork version label | About page and logs show `PiDoH <version> (Technitium <upstream>)` via `fork.json` |
| Configurable DoH landing page | Custom HTML served at the DoH root URL, configured via Settings |
| Hardcoded update URL | Update mechanism points to fork's `update.json` on GitHub |
| Block List Management tab | Web UI tab with per-URL download status, domain checker, allow/block list management |
| CNAME chain resolution | Domain checker follows CNAME chains and checks each entry against blocklists and AllowedZone |
| AllowedZone integration | Domain checker checks manual allowed zones (Settings > Other Zones > Allowed Zone) and shows `allowedBy` source |
| isBlocked + isAllowed overlap | When a domain is both blocked and allowed, UI shows ALLOWED banner with blocklist sources listed |
| Download status tracking | Per-URL download status (success/failed/skipped) with last updated timestamp and error messages |
| Loopback recursion exemption | Localhost queries bypass encrypted-only recursion requirement |
