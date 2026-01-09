# DocSeal Deployment Guide

This guide covers deploying DocSeal using Docker containers and managing releases.

## Table of Contents

- [Quick Start with Docker](#quick-start-with-docker)
- [Using docker-compose](#using-docker-compose)
- [Creating a Release](#creating-a-release)
- [CI/CD Pipeline](#cicd-pipeline)
- [Development with Docker](#development-with-docker)

## Quick Start with Docker

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+ (for docker-compose method)

### Running the Docker Image

Pull and run the latest DocSeal image:

```bash
# Pull the image from GitHub Container Registry
docker pull ghcr.io/yourusername/docseal:latest

# View help
docker run --rm ghcr.io/yourusername/docseal:latest --help

# Create a CA
docker run --rm \
  -v $(pwd)/data:/home/docseal/data \
  ghcr.io/yourusername/docseal:latest \
  ca init --password mypassword123
```

### Mounting Volumes

DocSeal needs access to your documents and certificates. Mount volumes for:

```bash
docker run --rm \
  -v $(pwd)/documents:/home/docseal/data/documents \
  -v $(pwd)/certs:/home/docseal/data/certs \
  -v $(pwd)/signatures:/home/docseal/data/signatures \
  ghcr.io/yourusername/docseal:latest \
  sign --help
```

## Using docker-compose

The easiest way to run DocSeal with all necessary mounts and configuration.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/docseal.git
cd docseal

# Start the container
docker-compose up -d docseal

# Run a command
docker-compose exec docseal ca init --password mypassword123

# Stop the container
docker-compose down
```

### Directory Structure

The docker-compose.yml creates these mounted directories:

```
.
├── documents/      # Place your documents here
├── certs/          # CA certificates and keys
├── signatures/     # Generated signatures
└── logs/           # Application logs
```

### Available Services

1. **docseal** - Production image (lightweight)
2. **docseal-dev** - Development image (with source code mounted)

## Creating a Release

### Version Tagging

DocSeal follows semantic versioning (MAJOR.MINOR.PATCH).

```bash
# Create a new tag
git tag v0.2.0

# Push the tag to GitHub
git push origin v0.2.0
```

### Automated Release Process

When you push a tag matching `v*.*.*`, GitHub Actions automatically:

1. **Runs Tests** - Validates all tests pass
2. **Builds Docker Image** - Creates optimized Docker image
3. **Publishes to PyPI** - Releases Python package
4. **Creates GitHub Release** - Generates release notes with changelog

### Release Checklist

Before releasing, ensure:

```bash
# 1. All tests pass
pytest tests/ -v

# 2. Code quality checks pass
ruff check src/
black --check src/ tests/
mypy src/docseal

# 3. Update version in pyproject.toml
# 4. Update CHANGELOG if present
# 5. Create annotated tag
git tag -a v0.2.0 -m "Release version 0.2.0"

# 6. Push tag
git push origin v0.2.0
```

## CI/CD Pipeline

### Workflow Stages

#### 1. Continuous Integration (CI)
- Runs on every push and PR
- File: `.github/workflows/ci.yml`
- Checks:
  - Code formatting (black, ruff)
  - Type checking (mypy)
  - Unit tests (pytest)
  - Security scanning

#### 2. Continuous Deployment (CD)
- Runs only on version tags (v*.*.*)
- File: `.github/workflows/cd.yml`
- Jobs:
  - **test** - Runs full test suite
  - **build-and-push-docker** - Builds and pushes Docker image
  - **publish-pypi** - Publishes to PyPI
  - **release** - Creates GitHub Release
  - **docker-test** - Tests the Docker image
  - **notify** - Sends completion notification

### Docker Image Tags

Each release creates multiple image tags:

```bash
# Version tag (e.g., v0.2.0)
ghcr.io/yourusername/docseal:v0.2.0

# Short version (e.g., 0.2.0)
ghcr.io/yourusername/docseal:0.2.0

# Latest
ghcr.io/yourusername/docseal:latest
```

### PyPI Package

```bash
# Install specific version
pip install docseal==0.2.0

# Install latest
pip install docseal
```

## Development with Docker

### Build Development Image

```bash
# Build the development image
docker build -f Dockerfile.dev -t docseal:dev .

# Or use docker-compose
docker-compose up -d docseal-dev
```

### Running Tests in Container

```bash
docker-compose run --rm docseal-dev pytest tests/ -v

# With coverage
docker-compose run --rm docseal-dev pytest tests/ --cov=src/docseal
```

### Interactive Development

```bash
# Shell into the container
docker-compose exec docseal-dev bash

# Run docseal directly
docker-compose exec docseal-dev docseal --help

# Run pytest interactively
docker-compose exec docseal-dev pytest tests/ -v -s
```

## Environment Variables

DocSeal respects these environment variables in containers:

```bash
# Python settings
PYTHONUNBUFFERED=1      # Unbuffered output
PYTHONDONTWRITEBYTECODE=1  # Don't write .pyc files

# DocSeal settings
DOCSEAL_CA_PASSWORD     # CA password (for automation)
DOCSEAL_LOG_LEVEL       # Logging level (DEBUG, INFO, WARNING, ERROR)
```

## Troubleshooting

### Permission Denied Errors

If you get permission errors when accessing mounted volumes:

```bash
# Fix with proper permissions
sudo chown -R 1000:1000 documents/ certs/ signatures/
```

### Docker Not Found

Ensure Docker is installed and running:

```bash
docker --version
docker ps
```

### Image Pull Errors

Authenticate with GitHub Container Registry:

```bash
docker login ghcr.io
# Use your GitHub username and personal access token
```

## Security Considerations

1. **Non-root User** - DocSeal runs as UID 1000 (docseal) in containers
2. **Minimal Image** - Uses python:3.11-slim for smaller attack surface
3. **No Secrets in Image** - Credentials should be passed via volumes/environment
4. **Health Checks** - Built-in health checks for orchestration systems

## Production Deployment

### Kubernetes Example

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: docseal
spec:
  containers:
  - name: docseal
    image: ghcr.io/yourusername/docseal:latest
    volumeMounts:
    - name: data
      mountPath: /home/docseal/data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: docseal-pvc
```

### Docker Swarm Example

```bash
docker service create \
  --name docseal \
  --mount type=bind,source=$(pwd)/data,target=/home/docseal/data \
  ghcr.io/yourusername/docseal:latest
```

## Getting Help

- 📚 [GitHub Issues](https://github.com/yourusername/docseal/issues)
- 📖 [Documentation](https://github.com/yourusername/docseal/blob/main/README.md)
- 💬 [Discussions](https://github.com/yourusername/docseal/discussions)

## License

DocSeal is released under the MIT License. See LICENSE file for details.
