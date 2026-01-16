# Docker Setup Summary

This document summarizes the Docker setup for DocSeal.

## Files Created

### Docker Configuration
- ✅ `Dockerfile` - Production multi-stage build
- ✅ `Dockerfile.dev` - Development image with dev dependencies
- ✅ `docker-compose.yml` - Easy local deployment
- ✅ `.dockerignore` - Optimized build context

### GitHub Actions
- ✅ `.github/workflows/ci.yml` - Continuous Integration
- ✅ `.github/workflows/cd.yml` - Continuous Deployment

### Documentation
- ✅ `DOCKER.md` - Complete Docker usage guide
- ✅ `scripts/validate-docker.sh` - Validation script

## Quick Test

```bash
# Validate setup
./scripts/validate-docker.sh

# Build image
docker build -t docseal:latest .

# Test image
docker run --rm docseal:latest --version
docker run --rm docseal:latest --help

# Use docker-compose
docker-compose up -d docseal
docker-compose exec docseal ca init --password testpass123
```

## Release Process

1. Update version in `pyproject.toml`
2. Create and push tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. GitHub Actions will automatically:
   - Run tests
   - Build Docker image
   - Push to GitHub Container Registry
   - Publish to PyPI
   - Create GitHub Release

## Image Location

After release, images will be available at:
- `ghcr.io/YOUR_USERNAME/docseal:latest`
- `ghcr.io/YOUR_USERNAME/docseal:v0.1.0`

## Setup Requirements

### For GitHub Actions to work:

1. **PyPI Token** (for publishing):
   - Create token at https://pypi.org/manage/account/tokens/
   - Add as secret `PYPI_API_TOKEN` in repository settings

2. **GitHub Container Registry**:
   - Automatically available via `GITHUB_TOKEN`
   - No additional setup needed

## Notes

- Docker images run as non-root user (UID 1000)
- CA data is stored in Docker volumes for persistence
- Use docker-compose for easiest local development
- Production images are multi-stage builds for minimal size

## Troubleshooting

If Docker build fails:
1. Check Docker is running: `docker ps`
2. Validate Dockerfile: `docker build --dry-run .` (if supported)
3. Check .dockerignore isn't excluding needed files
4. Review build logs for specific errors

For more details, see [DOCKER.md](./DOCKER.md).

