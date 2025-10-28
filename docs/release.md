# Release Process

This document describes the release process for tlscheck, including building binaries,
creating container images, and publishing releases on GitHub.

## Overview

The release process is automated through GitHub Actions and supports:

- **Cross-platform binary builds**: Linux, macOS, and Windows for both amd64 and arm64 architectures
- **Container images**: Multi-architecture Docker images published to GitHub Container Registry (ghcr.io)
- **Automated releases**: GitHub releases created automatically when tags are pushed

## Release Types

### Production Releases

Production releases are triggered by pushing a version tag (format: `v*`, e.g., `v1.0.0`).

**What happens:**
1. Builds binaries for all supported platforms (Linux, macOS, Windows on amd64 and arm64)
2. Generates SHA256 checksums for all binaries
3. Builds and pushes multi-architecture Docker images to `ghcr.io/programmerq/tlscheck`
4. Creates a GitHub release with all artifacts and release notes

**Docker image tags created:**
- `ghcr.io/programmerq/tlscheck:v1.0.0` (exact version)
- `ghcr.io/programmerq/tlscheck:1.0` (minor version)
- `ghcr.io/programmerq/tlscheck:1` (major version)

### Main Branch Builds

Builds are automatically created for pushes to the `main` branch, but only container images
are published (no binary artifacts or GitHub releases).

**What happens:**
1. Builds and pushes multi-architecture Docker images to `ghcr.io/programmerq/tlscheck`

**Docker image tags created:**
- `ghcr.io/programmerq/tlscheck:main` (latest main build)
- `ghcr.io/programmerq/tlscheck:<short-sha>` (specific commit)

**Note:** Binary artifacts are NOT built for main branch pushes, only for tagged releases.

## Prerequisites

Before creating your first release, ensure the following manual setup steps are completed:

### 1. GitHub Container Registry Access

The repository must have permission to publish to GitHub Container Registry (ghcr.io).
This is automatically enabled for repositories, but you may need to verify package visibility:

1. Go to the repository Settings → Actions → General
2. Under "Workflow permissions", ensure "Read and write permissions" is selected
3. Check "Allow GitHub Actions to create and approve pull requests" if needed

### 2. Verify GitHub Actions Workflows

Ensure the following workflows exist in `.github/workflows/`:
- `release.yml` - Handles tagged releases
- `docker-main.yml` - Handles main branch Docker builds
- `pr-checks.yml` - Runs on pull requests (already exists)

### 3. Enable GitHub Packages

After the first release, you may need to make the package public:

1. Go to the repository's main page
2. Click on "Packages" in the right sidebar
3. Click on the `tlscheck` package
4. Go to "Package settings"
5. Under "Danger Zone", change visibility to "Public" if desired

## Creating a Release

### Step 1: Prepare the Release

1. Ensure all changes are merged to `main`
2. Update version references in documentation if needed
3. Verify tests pass: `go test ./...`
4. Build locally to verify: `make release`

### Step 2: Create and Push a Tag

```bash
# Ensure you're on main and up to date
git checkout main
git pull origin main

# Create an annotated tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push the tag to GitHub
git push origin v1.0.0
```

### Step 3: Monitor the Release Workflow

1. Go to the repository's Actions tab
2. Watch the "Release" workflow execute
3. The workflow will:
   - Build binaries (takes ~2-3 minutes)
   - Build and push Docker images (takes ~5-10 minutes for multi-arch)
   - Create the GitHub release (takes ~1 minute)

### Step 4: Verify the Release

1. Check the Releases page for the new release with all artifacts
2. Verify the Docker images are published:
   ```bash
   docker pull ghcr.io/programmerq/tlscheck:v1.0.0
   docker run --rm ghcr.io/programmerq/tlscheck:v1.0.0 --version
   ```
3. Download and test a binary from the release page

## Building Locally

You can build binaries locally using the Makefile:

```bash
# Build for current platform
make build

# Build for all platforms
make release

# Build for specific platforms
make release-linux      # Linux amd64 and arm64
make release-darwin     # macOS amd64 and arm64
make release-windows    # Windows amd64 and arm64

# Build for a specific target
make release-linux-amd64
make release-darwin-arm64
make release-windows-amd64
```

Built binaries will be placed in the `dist/` directory.

### Setting Version Manually

You can override the version when building:

```bash
VERSION=v1.0.0 make build
VERSION=v1.0.0 make release
```

### Building Docker Images Locally

```bash
# Build for current architecture
docker build -t tlscheck:local .

# Build for specific architecture
docker buildx build --platform linux/amd64 -t tlscheck:local-amd64 .
docker buildx build --platform linux/arm64 -t tlscheck:local-arm64 .

# Build multi-architecture image
docker buildx build --platform linux/amd64,linux/arm64 -t tlscheck:local .

# Build with specific version
docker build --build-arg VERSION=v1.0.0 -t tlscheck:v1.0.0 .
```

## Supported Platforms

### Binary Builds

| Platform | Architecture | Binary Name |
|----------|-------------|-------------|
| Linux | amd64 | `tlscheck-linux-amd64` |
| Linux | arm64 | `tlscheck-linux-arm64` |
| macOS | amd64 | `tlscheck-darwin-amd64` |
| macOS | arm64 | `tlscheck-darwin-arm64` |
| Windows | amd64 | `tlscheck-windows-amd64.exe` |
| Windows | arm64 | `tlscheck-windows-arm64.exe` |

### Container Images

Docker images are built for:
- `linux/amd64`
- `linux/arm64`

## Troubleshooting

### Release Workflow Fails

1. Check the Actions tab for error details
2. Common issues:
   - Build errors: Fix in code and create a new tag
   - Permission errors: Verify workflow permissions in Settings
   - Docker push errors: Ensure GITHUB_TOKEN has package write permissions

### Docker Image Not Available

1. Verify the workflow completed successfully
2. Check package visibility (may need to be set to public)
3. Ensure you're using the correct image name: `ghcr.io/programmerq/tlscheck`

### Binary Build Issues

1. Verify Go version matches `go.mod` (currently 1.24.3)
2. Ensure all dependencies are available: `go mod download`
3. Check for platform-specific issues in the code

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **Major version** (v1.0.0 → v2.0.0): Breaking changes
- **Minor version** (v1.0.0 → v1.1.0): New features, backwards compatible
- **Patch version** (v1.0.0 → v1.0.1): Bug fixes, backwards compatible

### Pre-release Versions

For pre-release versions, use the following formats:
- Alpha: `v1.0.0-alpha.1`
- Beta: `v1.0.0-beta.1`
- Release Candidate: `v1.0.0-rc.1`

GitHub Actions will mark these as "pre-release" automatically based on the tag format.

## Rollback Process

If a release needs to be rolled back:

1. Delete the GitHub release (does not delete the tag)
2. Delete the tag locally and remotely:
   ```bash
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```
3. Delete the Docker images from ghcr.io (go to Packages → Package settings)
4. Create a new fixed release with an incremented version

## Automation Details

### Makefile Targets

The Makefile provides the following targets for release automation:

- `make help` - Show available targets
- `make build` - Build for current platform
- `make test` - Run tests
- `make fmt` - Format code with gofmt
- `make clean` - Remove build artifacts
- `make release` - Build all release binaries
- `make deps` - Download and tidy dependencies

### GitHub Actions Workflows

#### release.yml (Tag-based releases)

**Trigger:** Push of any tag matching `v*`

**Jobs:**
1. `build-binaries`: Builds binaries for all platforms, creates checksums
2. `build-docker`: Builds and pushes multi-arch Docker images
3. `create-release`: Creates GitHub release with artifacts

**Permissions required:**
- `contents: write` (for creating releases)
- `packages: write` (for pushing Docker images)

#### docker-main.yml (Main branch builds)

**Trigger:** Push to `main` branch

**Jobs:**
1. `build-docker-main`: Builds and pushes multi-arch Docker images with `main` tag

**Permissions required:**
- `contents: read`
- `packages: write`

### Environment Variables

The following environment variables are used during builds:

- `VERSION`: Set automatically from git tag or can be overridden
- `GITHUB_TOKEN`: Automatically provided by GitHub Actions
- `GOOS`, `GOARCH`: Set by Makefile for cross-compilation

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitHub Packages Documentation](https://docs.github.com/en/packages)
- [Docker Buildx Documentation](https://docs.docker.com/buildx/working-with-buildx/)
- [Go Cross Compilation](https://go.dev/doc/install/source#environment)
