#!/bin/bash

# Build script for DefenraAgent on Linux
# Run this script on the Linux server to build the latest version

echo "🔨 Building DefenraAgent v1.2.2b for Linux..."

# Get current git commit
GIT_COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION="v1.2.2b"

echo "Version: $VERSION"
echo "Build Date: $BUILD_DATE"
echo "Git Commit: $GIT_COMMIT"

# Build the binary
go build -ldflags "-X main.Version=$VERSION -X main.BuildDate=$BUILD_DATE -X main.GitCommit=$GIT_COMMIT" -o defenra-agent .

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo "Binary: ./defenra-agent"
    
    # Show version
    echo ""
    echo "Version info:"
    ./defenra-agent version
    
    echo ""
    echo "To update the running agent:"
    echo "1. Stop the service: sudo systemctl stop defenra-agent"
    echo "2. Replace the binary: sudo cp defenra-agent /opt/defenra-agent/defenra-agent"
    echo "3. Start the service: sudo systemctl start defenra-agent"
    echo "4. Check logs: sudo journalctl -u defenra-agent -f"
else
    echo "❌ Build failed!"
    exit 1
fi