# Docker Guide for DocSeal

This guide explains how to use DocSeal with Docker for easy deployment and usage.

## Quick Start

### Pull and Run

```bash
# Pull the latest image from GitHub Container Registry
docker pull ghcr.io/YOUR_USERNAME/docseal:latest

# View help
docker run --rm ghcr.io/YOUR_USERNAME/docseal:latest --help

# Initialize CA
docker run --rm \
  -v docseal-ca:/home/docseal/.docseal/ca \
  ghcr.io/YOUR_USERNAME/docseal:latest \
  ca init --password mypassword123
```

## Using Docker Compose (Recommended)

The easiest way to use DocSeal is with docker-compose:

```bash
# Start the container
docker-compose up -d docseal

# Initialize CA
docker-compose exec docseal ca init --password mypassword123

# Issue a certificate
docker-compose exec docseal ca issue --name "John Doe" --role "Registrar"

# Sign a document (place it in ./data/documents/)
docker-compose exec docseal sign \
  --doc /home/docseal/data/documents/transcript.pdf \
  --cert /home/docseal/data/certs/john_doe.p12 \
  --out /home/docseal/data/signatures/transcript.sig

# Verify a signature
docker-compose exec docseal verify \
  --doc /home/docseal/data/documents/transcript.pdf \
  --sig /home/docseal/data/signatures/transcript.sig \
  --verbose
```

## Directory Structure

When using docker-compose, create these directories:

```bash
mkdir -p data/{documents,certs,signatures}
```

The container will mount:
- `./data/documents/` - Place your documents here
- `./data/certs/` - Place certificate files (.p12) here
- `./data/signatures/` - Generated signatures will be saved here
- `~/.docseal/ca/` - CA files (managed by Docker volume)

## Building from Source

### Production Image

```bash
# Build the production image
docker build -t docseal:latest -f Dockerfile .

# Run it
docker run --rm docseal:latest --help
```

### Development Image

```bash
# Build the development image
docker build -t docseal:dev -f Dockerfile.dev .

# Run with source code mounted
docker run --rm \
  -v $(pwd)/src:/app/src \
  -v $(pwd)/tests:/app/tests \
  docseal:dev pytest tests/ -v
```

## Volume Mounts

### Persistent CA Storage

```bash
# Use named volume (recommended)
docker run --rm \
  -v docseal-ca:/home/docseal/.docseal/ca \
  docseal:latest ca info

# Use bind mount (for backup/access)
docker run --rm \
  -v $(pwd)/ca-data:/home/docseal/.docseal/ca \
  docseal:latest ca info
```

### Document and Certificate Access

```bash
# Mount directories for documents, certs, and signatures
docker run --rm \
  -v $(pwd)/documents:/home/docseal/data/documents:ro \
  -v $(pwd)/certs:/home/docseal/data/certs:ro \
  -v $(pwd)/signatures:/home/docseal/data/signatures:rw \
  docseal:latest sign \
    --doc /home/docseal/data/documents/file.pdf \
    --cert /home/docseal/data/certs/cert.p12 \
    --out /home/docseal/data/signatures/file.sig
```

## Environment Variables

```bash
# Set environment variables
docker run --rm \
  -e DOCSEAL_HOME=/custom/path \
  -e PYTHONUNBUFFERED=1 \
  docseal:latest --help
```

## Security Considerations

1. **Non-root User**: DocSeal runs as user `docseal` (UID 1000) inside containers
2. **Password Security**: Never pass passwords via command line in production
3. **Volume Permissions**: Ensure mounted volumes have correct permissions:
   ```bash
   chown -R 1000:1000 data/
   ```

## Troubleshooting

### Permission Denied

If you get permission errors:

```bash
# Fix permissions
sudo chown -R 1000:1000 data/
```

### CA Not Found

If the CA isn't found, ensure the volume is mounted:

```bash
# Check if volume exists
docker volume ls | grep docseal-ca

# Create and use volume
docker volume create docseal-ca
docker run --rm -v docseal-ca:/home/docseal/.docseal/ca docseal:latest ca info
```

### Image Not Found

If using GitHub Container Registry:

```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Pull the image
docker pull ghcr.io/YOUR_USERNAME/docseal:latest
```

## Production Deployment

### Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: docseal
spec:
  containers:
  - name: docseal
    image: ghcr.io/YOUR_USERNAME/docseal:latest
    volumeMounts:
    - name: ca-data
      mountPath: /home/docseal/.docseal/ca
    - name: documents
      mountPath: /home/docseal/data/documents
  volumes:
  - name: ca-data
    persistentVolumeClaim:
      claimName: docseal-ca-pvc
  - name: documents
    persistentVolumeClaim:
      claimName: docseal-docs-pvc
```

### Docker Swarm

```bash
docker service create \
  --name docseal \
  --mount type=volume,source=docseal-ca,target=/home/docseal/.docseal/ca \
  --mount type=bind,source=$(pwd)/data,target=/home/docseal/data \
  ghcr.io/YOUR_USERNAME/docseal:latest
```

## Development Workflow

### Using docker-compose for Development

```bash
# Start development container
docker-compose up -d docseal-dev

# Run tests
docker-compose exec docseal-dev pytest tests/ -v

# Run linting
docker-compose exec docseal-dev ruff check src/

# Interactive shell
docker-compose exec docseal-dev bash
```

## Image Tags

When pulling from GitHub Container Registry:

- `ghcr.io/YOUR_USERNAME/docseal:latest` - Latest release
- `ghcr.io/YOUR_USERNAME/docseal:v0.1.0` - Specific version
- `ghcr.io/YOUR_USERNAME/docseal:0.1.0` - Short version tag

## Health Checks

The Docker image includes a health check:

```bash
# Check container health
docker ps

# Inspect health status
docker inspect --format='{{.State.Health.Status}}' <container-id>
```

## Best Practices

1. **Use docker-compose** for local development and testing
2. **Use named volumes** for CA data persistence
3. **Never commit** CA private keys or certificates to git
4. **Backup** the CA volume regularly
5. **Use specific version tags** in production, not `latest`

## Support

For issues or questions:
- GitHub Issues: https://github.com/YOUR_USERNAME/docseal/issues
- Documentation: See README.md

