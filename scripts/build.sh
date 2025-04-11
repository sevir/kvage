#!/bin/bash

# Set the binary name
BINARY_NAME="kvage"
MAIN_PATH="./src"
VERSION="v1.11.0"

# Helper function to zip a binary
zip_binary() {
    local binary=$1
    cd build
    zip -j "${binary}.zip" "${binary}"
    rm "${binary}"  # Remove the original binary
    cd ..
}

# Create output directory
mkdir -p build

# clean up
rm -rf build/*

# Build for Windows (amd64)
GOOS=windows GOARCH=amd64 go build -ldflags "-X 'main.Version=${VERSION}'" -o "build/${BINARY_NAME}-windows-amd64.exe" $MAIN_PATH

# Build for Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-X 'main.Version=${VERSION}'" -o "build/${BINARY_NAME}-linux-amd64" $MAIN_PATH
GOOS=linux GOARCH=arm64 go build -ldflags "-X 'main.Version=${VERSION}'" -o "build/${BINARY_NAME}-linux-arm64" $MAIN_PATH
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X 'main.Version=${VERSION}'" -o "build/${BINARY_NAME}-linux-amd64-musl" $MAIN_PATH

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -ldflags "-X 'main.Version=${VERSION}'" -o "build/${BINARY_NAME}-darwin-amd64" $MAIN_PATH
GOOS=darwin GOARCH=arm64 go build -ldflags "-X 'main.Version=${VERSION}'" -o "build/${BINARY_NAME}-darwin-arm64" $MAIN_PATH

# Make Linux and macOS binaries executable
chmod +x build/${BINARY_NAME}-linux-*
chmod +x build/${BINARY_NAME}-darwin-*

# Zip each binary
for binary in build/${BINARY_NAME}-*; do
    if [ -f "$binary" ]; then
        zip_binary $(basename "$binary")
    fi
done

echo "Build complete! Zipped binaries are in the build directory."

