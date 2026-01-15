package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	githubAPIURL     = "https://api.github.com/repos/Defenra/DefenraAgent/releases/latest"
	githubReleaseURL = "https://github.com/Defenra/DefenraAgent/releases/download"
	updateTimeout    = 5 * time.Minute
)

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckForUpdate checks if a newer version is available
func CheckForUpdate(currentVersion string) (bool, string, error) {
	if currentVersion == "dev" {
		return false, "", fmt.Errorf("development version cannot be updated via this command")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return false, "", fmt.Errorf("failed to parse release data: %w", err)
	}

	latestVersion := release.TagName

	// Compare versions (simple string comparison for semver)
	if latestVersion == currentVersion {
		return false, currentVersion, nil
	}

	// Check if latest is actually newer (basic check)
	if compareVersions(latestVersion, currentVersion) > 0 {
		return true, latestVersion, nil
	}

	return false, currentVersion, nil
}

// PerformUpdate downloads and installs the latest version
func PerformUpdate(currentVersion string) error {
	hasUpdate, latestVersion, err := CheckForUpdate(currentVersion)
	if err != nil {
		return err
	}

	if !hasUpdate {
		fmt.Printf("✓ Already running the latest version: %s\n", currentVersion)
		return nil
	}

	fmt.Printf("📦 New version available: %s → %s\n", currentVersion, latestVersion)
	fmt.Println("⬇️  Downloading update...")

	// Determine platform-specific binary name
	binaryName := getBinaryName()
	archiveName := fmt.Sprintf("%s.tar.gz", binaryName)
	checksumName := fmt.Sprintf("%s.sha256", archiveName)

	// Download URLs
	archiveURL := fmt.Sprintf("%s/%s/%s", githubReleaseURL, latestVersion, archiveName)
	checksumURL := fmt.Sprintf("%s/%s/%s", githubReleaseURL, latestVersion, checksumName)

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "defenra-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, archiveName)
	checksumPath := filepath.Join(tempDir, checksumName)

	// Download archive
	if err := downloadFile(archiveURL, archivePath); err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}

	// Download checksum
	if err := downloadFile(checksumURL, checksumPath); err != nil {
		return fmt.Errorf("failed to download checksum: %w", err)
	}

	fmt.Println("🔐 Verifying checksum...")

	// Verify checksum
	if err := verifyChecksum(archivePath, checksumPath); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	fmt.Println("📂 Extracting update...")

	// Extract archive
	extractedBinary := filepath.Join(tempDir, binaryName)
	if err := extractTarGz(archivePath, tempDir); err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}

	// Get current executable path
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Resolve symlinks
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	fmt.Println("🔄 Installing update...")

	// Backup current binary
	backupPath := currentExe + ".backup"
	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Copy new binary
	if err := copyFile(extractedBinary, currentExe); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(currentExe, 0755); err != nil {
		// Restore backup on failure
		os.Remove(currentExe)
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Remove backup
	os.Remove(backupPath)

	fmt.Printf("✅ Successfully updated to version %s\n", latestVersion)
	fmt.Println("🔄 Please restart the agent for changes to take effect")

	return nil
}

// getBinaryName returns the platform-specific binary name
func getBinaryName() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	return fmt.Sprintf("defenra-agent-%s-%s", osName, arch)
}

// downloadFile downloads a file from URL to filepath
func downloadFile(url, filepath string) error {
	client := &http.Client{Timeout: updateTimeout}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// verifyChecksum verifies the SHA256 checksum of a file
func verifyChecksum(filePath, checksumPath string) error {
	// Read expected checksum
	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	// Parse checksum file (format: "hash  filename")
	parts := strings.Fields(string(checksumData))
	if len(parts) < 1 {
		return fmt.Errorf("invalid checksum file format")
	}
	expectedChecksum := parts[0]

	// Calculate actual checksum
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// extractTarGz extracts a tar.gz archive to a directory
func extractTarGz(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeReg:
			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()

			// Set file permissions
			if err := os.Chmod(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// compareVersions compares two semantic version strings
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func compareVersions(v1, v2 string) int {
	// Remove 'v' prefix if present
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	// Simple string comparison for now
	// TODO: Implement proper semver comparison if needed
	if v1 > v2 {
		return 1
	}
	if v1 < v2 {
		return -1
	}
	return 0
}
