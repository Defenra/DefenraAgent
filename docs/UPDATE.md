# Self-Update Feature

DefenraAgent includes a built-in self-update mechanism that allows you to easily upgrade to the latest version from GitHub releases.

## Commands

### Check for Updates

Check if a newer version is available without installing it:

```bash
defenra-agent check-update
```

**Example output:**
```
🔍 Checking for updates...
Current version: v1.0.0
✨ New version available: v1.1.0

To update, run:
  sudo defenra-agent update
```

### Update to Latest Version

Download and install the latest version:

```bash
sudo defenra-agent update
```

**Note:** Requires `sudo` on Linux/macOS because the agent binary is typically installed in a system directory.

**Example output:**
```
🔍 Checking for updates...
Current version: v1.0.0

📦 New version available: v1.0.0 → v1.1.0
⬇️  Downloading update...
🔐 Verifying checksum...
📂 Extracting update...
🔄 Installing update...
✅ Successfully updated to version v1.1.0
🔄 Please restart the agent for changes to take effect
```

### Show Version

Display current version information:

```bash
defenra-agent version
```

**Example output:**
```
Defenra Agent
Version:    v1.0.0
Build Date: 2024-01-15T10:30:00Z
Git Commit: abc12345
Go Version: go1.21+
OS/Arch:    linux/amd64
```

## How It Works

1. **Check GitHub Releases**: The updater queries the GitHub API for the latest release
2. **Compare Versions**: Compares the current version with the latest available version
3. **Download Binary**: Downloads the platform-specific binary (e.g., `defenra-agent-linux-amd64.tar.gz`)
4. **Verify Checksum**: Verifies the SHA256 checksum to ensure integrity
5. **Extract Archive**: Extracts the binary from the tar.gz archive
6. **Backup & Replace**: Backs up the current binary and replaces it with the new one
7. **Set Permissions**: Sets executable permissions on the new binary

## Security

### Checksum Verification

Every release includes SHA256 checksums. The updater automatically verifies the downloaded file matches the expected checksum before installation.

### HTTPS Only

All downloads are performed over HTTPS to prevent man-in-the-middle attacks.

### Backup & Rollback

The current binary is backed up before replacement. If the update fails, the backup is automatically restored.

## Supported Platforms

The self-update feature works on all platforms where DefenraAgent is released:

- Linux (AMD64, ARM64)
- macOS (AMD64, ARM64/M1/M2)
- FreeBSD (AMD64, ARM64)

The updater automatically detects your platform and downloads the correct binary.

## Limitations

### Development Builds

Development builds (version = "dev") cannot be updated via this mechanism. You must build from source or download a release manually.

```bash
$ defenra-agent check-update
🔍 Checking for updates...
Current version: dev
❌ Failed to check for updates: development version cannot be updated via this command
```

### Systemd Service

If the agent is running as a systemd service, you need to restart the service after updating:

```bash
# Update the binary
sudo defenra-agent update

# Restart the service
sudo systemctl restart defenra-agent
```

### Permissions

The update command requires write permissions to the agent binary location. On Linux/macOS, this typically requires `sudo`.

## Troubleshooting

### "Permission denied" error

**Problem:** Cannot write to the binary location.

**Solution:** Run with `sudo`:
```bash
sudo defenra-agent update
```

### "Checksum verification failed"

**Problem:** Downloaded file doesn't match expected checksum.

**Solution:** This could indicate a corrupted download or security issue. Try again:
```bash
sudo defenra-agent update
```

If the problem persists, download manually from GitHub releases.

### "Failed to fetch latest release"

**Problem:** Cannot connect to GitHub API.

**Solution:** 
- Check your internet connection
- Verify GitHub is accessible: `curl https://api.github.com`
- Check if you're behind a proxy or firewall

### Update fails but agent still works

The updater creates a backup before replacing the binary. If the update fails, the backup is automatically restored, so your agent continues to work with the old version.

## Manual Update

If the self-update feature doesn't work, you can always update manually:

1. Download the latest release from [GitHub Releases](https://github.com/Defenra/DefenraAgent/releases)
2. Verify the checksum:
   ```bash
   sha256sum -c defenra-agent-linux-amd64.tar.gz.sha256
   ```
3. Extract the archive:
   ```bash
   tar -xzf defenra-agent-linux-amd64.tar.gz
   ```
4. Replace the binary:
   ```bash
   sudo mv defenra-agent-linux-amd64 /usr/local/bin/defenra-agent
   sudo chmod +x /usr/local/bin/defenra-agent
   ```
5. Restart the agent:
   ```bash
   sudo systemctl restart defenra-agent
   ```

## Automation

You can automate update checks using cron:

```bash
# Check for updates daily at 3 AM
0 3 * * * /usr/local/bin/defenra-agent check-update
```

For automatic updates (use with caution):

```bash
# Auto-update weekly on Sunday at 3 AM
0 3 * * 0 /usr/local/bin/defenra-agent update && systemctl restart defenra-agent
```

**Warning:** Automatic updates can cause unexpected downtime. Always test updates in a staging environment first.

## API Rate Limits

The GitHub API has rate limits:
- **Unauthenticated**: 60 requests per hour
- **Authenticated**: 5000 requests per hour

The updater uses unauthenticated requests, which is sufficient for normal usage. If you need higher limits, you can set a GitHub token (future feature).

## Related Documentation

- [Installation Guide](../INSTALL_GUIDE.md)
- [Quick Start](../QUICKSTART.md)
- [Release Process](../RELEASE.md)
- [GitHub Releases](https://github.com/Defenra/DefenraAgent/releases)
