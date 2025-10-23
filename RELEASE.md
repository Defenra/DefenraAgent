# Release Process

This document describes how to create a new release of Defenra Agent.

## 🎯 Quick Start - Creating First Release

### Method 1: GitHub UI (Recommended for v1.0.0)

1. **Go to GitHub Actions**
   ```
   https://github.com/Defenra/DefenraAgent/actions
   ```

2. **Run "Tag and Release" Workflow**
   - Click on "Tag and Release" in left sidebar
   - Click "Run workflow" button
   - Enter version: `1.0.0` (without 'v')
   - Click "Run workflow"

3. **Wait (~5 minutes)**
   - Workflow creates tag `v1.0.0`
   - Builds binaries for all platforms
   - Creates GitHub Release
   - Publishes Docker images

4. **Verify**
   ```
   https://github.com/Defenra/DefenraAgent/releases/tag/v1.0.0
   ```

### Method 2: Command Line

```bash
# Update CHANGELOG.md first
nano CHANGELOG.md

# Commit and create tag
git add CHANGELOG.md
git commit -m "Release v1.0.0"
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

---

## Automated Release Process

Defenra Agent uses GitHub Actions to automatically build and publish releases when a version tag is pushed.

### Creating a New Release

#### Option 1: Using GitHub UI (Recommended)

1. **Go to GitHub Actions**
   - Navigate to: https://github.com/Defenra/DefenraAgent/actions
   - Click on "Tag and Release" workflow

2. **Run Workflow**
   - Click "Run workflow" button
   - Enter version number (e.g., `1.0.0`)
   - Select if it's a pre-release
   - Click "Run workflow"

3. **Wait for Completion**
   - The workflow will:
     - Create a git tag (`v1.0.0`)
     - Update CHANGELOG.md
     - Trigger the release build
   
4. **Edit Release Notes**
   - After the release is created, edit CHANGELOG.md with actual changes
   - Commit and push changes

#### Option 2: Manual Tag Creation

1. **Update CHANGELOG.md**
   ```bash
   # Add new version section
   nano CHANGELOG.md
   ```

2. **Commit Changes**
   ```bash
   git add CHANGELOG.md
   git commit -m "Release v1.0.0"
   ```

3. **Create Tag**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   ```

4. **Push Tag**
   ```bash
   git push origin v1.0.0
   ```

5. **Monitor Build**
   - GitHub Actions will automatically:
     - Build binaries for multiple platforms
     - Create GitHub Release
     - Upload artifacts
     - Update Docker Hub

## What Gets Built

The release workflow builds binaries for:

- **Linux AMD64** (x86_64)
- **Linux ARM64** (aarch64)
- **macOS AMD64** (Intel)
- **macOS ARM64** (Apple Silicon M1/M2)

Each binary is:
- Compiled with optimizations (`-ldflags "-s -w"`)
- Version information embedded
- Compressed to `.tar.gz`
- SHA256 checksum generated
- Uploaded to GitHub Release

## Release Artifacts

For version `v1.0.0`, the following files are created:

```
defenra-agent-linux-amd64.tar.gz
defenra-agent-linux-amd64.tar.gz.sha256
defenra-agent-linux-arm64.tar.gz
defenra-agent-linux-arm64.tar.gz.sha256
defenra-agent-darwin-amd64.tar.gz
defenra-agent-darwin-amd64.tar.gz.sha256
defenra-agent-darwin-arm64.tar.gz
defenra-agent-darwin-arm64.tar.gz.sha256
```

## Version Information

Version information is embedded in the binary using ldflags:

```go
// version.go
var (
    Version   = "dev"      // Set to "v1.0.0"
    BuildDate = "unknown"  // Set to "2025-10-23T10:15:30Z"
    GitCommit = "unknown"  // Set to "abc12345"
)
```

Check version:
```bash
./defenra-agent --version  # TODO: Add --version flag
```

## Docker Images

Docker images are automatically built and pushed to Docker Hub:

- `defenra/agent:1.0.0` (version tag)
- `defenra/agent:latest` (latest release)

Platforms:
- `linux/amd64`
- `linux/arm64`

## Release Checklist

Before creating a release:

- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated with changes
- [ ] Version number follows [Semantic Versioning](https://semver.org/)
- [ ] No critical bugs
- [ ] Code reviewed

After release is created:

- [ ] Verify all artifacts uploaded
- [ ] Test installation script with new version
- [ ] Verify Docker image works
- [ ] Update documentation if needed
- [ ] Announce release

## Versioning

We follow [Semantic Versioning](https://semver.org/) (SemVer):

- **MAJOR** version (1.x.x): Incompatible API changes
- **MINOR** version (x.1.x): New functionality, backwards compatible
- **PATCH** version (x.x.1): Bug fixes, backwards compatible

### Examples

- `1.0.0` - Initial release
- `1.1.0` - New feature (GeoDNS improvements)
- `1.1.1` - Bug fix (memory leak fix)
- `2.0.0` - Breaking change (config format change)

### Pre-releases

Pre-release versions can be tagged:

- `v1.0.0-alpha.1` - Alpha release
- `v1.0.0-beta.1` - Beta release
- `v1.0.0-rc.1` - Release candidate

## GitHub Actions Workflows

### release.yml

Triggered by: Tag push (`v*.*.*`)

Steps:
1. **Build** - Compile binaries for all platforms
2. **Create Release** - Create GitHub release with notes
3. **Docker Build** - Build and push Docker images

### tag-release.yml

Triggered by: Manual workflow dispatch

Steps:
1. Validate version format
2. Check if tag exists
3. Update CHANGELOG.md
4. Create and push tag
5. Trigger release workflow

### test.yml

Triggered by: Push to main/develop (excluding tags)

Steps:
1. Run tests
2. Run linter
3. Build binaries (test only)

## Installation Script Integration

The `install.sh` script automatically:
1. Detects platform (OS and architecture)
2. Fetches latest release from GitHub API
3. Downloads pre-built binary
4. Verifies SHA256 checksum
5. Falls back to building from source if download fails

Users don't need to manually download binaries.

## Rollback

To rollback a release:

1. **Mark as Pre-release**
   - Go to GitHub Releases
   - Edit the release
   - Check "This is a pre-release"

2. **Delete Release** (if needed)
   - Delete release from GitHub
   - Delete tag: `git push --delete origin v1.0.0`
   - Delete local tag: `git tag -d v1.0.0`

3. **Create Fixed Release**
   - Fix the issue
   - Create new release with patch version

## Troubleshooting

### Build Fails

**Problem:** Build fails in GitHub Actions

**Solutions:**
- Check Go version compatibility
- Verify all dependencies available
- Check build logs for errors
- Test build locally first

### Docker Push Fails

**Problem:** Docker image push fails

**Solutions:**
- Verify Docker Hub credentials in secrets
- Check Docker Hub repository exists
- Verify repository permissions

### Binary Download Fails

**Problem:** Users report install.sh can't download binary

**Solutions:**
- Verify release artifacts uploaded correctly
- Check GitHub API rate limits
- Verify binary names match expected format
- Check network connectivity

## Manual Release (Emergency)

If GitHub Actions fails, create release manually:

1. **Build Binaries Locally**
   ```bash
   # Linux AMD64
   GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o defenra-agent-linux-amd64 .
   tar -czf defenra-agent-linux-amd64.tar.gz defenra-agent-linux-amd64
   sha256sum defenra-agent-linux-amd64.tar.gz > defenra-agent-linux-amd64.tar.gz.sha256
   
   # Repeat for other platforms
   ```

2. **Create GitHub Release**
   - Go to: https://github.com/Defenra/DefenraAgent/releases/new
   - Enter tag version
   - Add release notes
   - Upload artifacts
   - Publish release

## Security

### Artifact Signing

Future enhancement: Sign release artifacts with GPG

```bash
gpg --detach-sign --armor defenra-agent-linux-amd64.tar.gz
```

### Checksum Verification

Users should verify checksums:

```bash
sha256sum -c defenra-agent-linux-amd64.tar.gz.sha256
```

The install.sh script automatically verifies checksums.

## Contact

For release-related questions:
- GitHub Issues: https://github.com/Defenra/DefenraAgent/issues
- Email: support@defenra.com

---

**Last Updated:** 2025-10-23
