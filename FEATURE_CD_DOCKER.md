# CD/Docker Deployment Feature

This branch (`feature/cd-docker-deployment`) adds comprehensive Continuous Deployment and Docker containerization to DocSeal.

## What's Included

### 1. 🐳 Docker Support
- **Dockerfile** - Production-ready multi-stage build with optimized image size
- **Dockerfile.dev** - Development image with source code mounted for local development
- **.dockerignore** - Optimized Docker build context

### 2. 📦 Docker Compose
- **docker-compose.yml** - Easy local deployment with volume mounts for:
  - Documents
  - Certificates
  - Signatures
  - Logs

### 3. 🚀 GitHub Actions CD Workflow
- **`.github/workflows/cd.yml`** - Automated pipeline triggered on version tags

**Workflow includes:**
- ✅ Full test suite execution
- 🐳 Docker image build and push to GitHub Container Registry (ghcr.io)
- 📦 Automatic PyPI package publishing
- 📝 GitHub Release creation with changelog
- 🧪 Docker image testing
- 📢 Success notifications

### 4. 📚 Documentation
- **DEPLOYMENT.md** - Complete deployment guide covering:
  - Quick start with Docker
  - docker-compose usage
  - Release process
  - CI/CD pipeline details
  - Troubleshooting
  - Production deployment examples

### 5. 🔧 Release Script
- **scripts/release.sh** - Automated release helper that:
  - Validates version format
  - Runs pre-release checks
  - Updates version in pyproject.toml
  - Creates annotated git tag
  - Provides push instructions

## Quick Start

### Local Development with Docker

```bash
# Start development container
docker-compose up -d docseal-dev

# Run tests
docker-compose run --rm docseal-dev pytest tests/ -v

# Open shell
docker-compose exec docseal-dev bash
```

### Production with Docker

```bash
# Build image
docker build -t docseal:latest .

# Run container
docker run --rm \
  -v $(pwd)/data:/home/docseal/data \
  docseal:latest --help
```

### Creating a Release

```bash
# Navigate to main/master branch
git checkout main

# Run release script
./scripts/release.sh v0.2.0

# Push to GitHub (triggers CD)
git push origin main && git push origin v0.2.0
```

The CD pipeline will automatically:
1. Run all tests
2. Build Docker image
3. Push to `ghcr.io/yourusername/docseal:0.2.0`
4. Publish to PyPI
5. Create GitHub Release

## Setup Requirements

Before merging, ensure:

### For GitHub Actions to work:

1. **PyPI Token** (for publishing to PyPI):
   - Create a token at https://pypi.org/manage/account/tokens/
   - Add as secret `PYPI_API_TOKEN` in repository settings

2. **GitHub Container Registry** (automatically available):
   - Actions use built-in `GITHUB_TOKEN`
   - Images pushed to `ghcr.io/yourusername/docseal`

### Local Setup:

```bash
# Make release script executable
chmod +x scripts/release.sh

# Update repository references in files:
# - DEPLOYMENT.md: Replace "yourusername" with your GitHub username
# - cd.yml: Verify workflow meets your needs
# - Dockerfile: Update LABEL url if using different repo
```

## File Structure

```
.
├── .dockerignore                 # Docker build context
├── Dockerfile                    # Production image
├── Dockerfile.dev               # Development image
├── docker-compose.yml           # Local deployment
├── DEPLOYMENT.md                # Deployment guide
├── scripts/
│   └── release.sh              # Release helper script
└── .github/workflows/
    └── cd.yml                  # CD pipeline
```

## Workflow Triggers

### Development Workflow (Existing)
- Runs on: Every push, every PR
- Checks: Format, types, tests, security

### CD Workflow (New)
- Runs on: Tag push matching `v*.*.*`
- Example: `git push origin v0.2.0`
- Publishes: Docker image + PyPI package + GitHub Release

## Security Features

- ✅ Non-root user (UID 1000) in containers
- ✅ Minimal base image (python:3.11-slim)
- ✅ Multi-stage builds (no build dependencies in final image)
- ✅ No secrets hardcoded (use volumes/env vars)
- ✅ Health checks for orchestration

## Docker Image Tags

Each release creates tags:

```bash
ghcr.io/yourusername/docseal:v0.2.0      # Full version tag
ghcr.io/yourusername/docseal:0.2.0       # Short version
ghcr.io/yourusername/docseal:latest      # Latest
```

## Environment Setup

Before merging this branch, update these placeholders:

1. **DEPLOYMENT.md** - Line 56, 138, 166
   ```bash
   # Find and replace
   sed -i 's/yourusername/YOUR_USERNAME/g' DEPLOYMENT.md
   ```

2. **.github/workflows/cd.yml** - Update repository references if needed

3. **Dockerfile** - Update LABEL url if using different repository path

## Next Steps

1. ✅ Create a PR from `feature/cd-docker-deployment` → `main`
2. ✅ Request review from team
3. ✅ Merge after approval
4. ✅ Create first release tag:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
5. ✅ Watch GitHub Actions workflow
6. ✅ Verify Docker image in ghcr.io
7. ✅ Verify package on PyPI

## Testing the Workflow

Before creating a real release, test with:

```bash
# Create test tag (won't publish)
git tag test-v0.1.0
git push origin test-v0.1.0

# Watch workflow at: https://github.com/yourusername/docseal/actions

# Delete test tag
git tag -d test-v0.1.0
git push origin :test-v0.1.0
```

## Troubleshooting

### PyPI Publishing Fails
- Ensure `PYPI_API_TOKEN` secret is set in repository
- Verify token has upload permissions
- Check token is not expired

### Docker Push Fails
- Verify GitHub Actions has write permissions to Container Registry
- Check that you're authenticated with correct credentials
- Ensure image name matches your repository path

### Release Script Issues
```bash
# Make script executable
chmod +x scripts/release.sh

# Run with verbose output
bash -x scripts/release.sh v0.2.0
```

## Related Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Complete deployment guide
- [.github/workflows/ci.yml](../.github/workflows/ci.yml) - CI workflow
- [Docker Docs](https://docs.docker.com/) - Docker reference
- [GitHub Actions Docs](https://docs.github.com/en/actions) - Actions reference

## Questions?

For questions about this feature, refer to:
- `DEPLOYMENT.md` for deployment-specific questions
- `.github/workflows/cd.yml` for workflow details
- `Dockerfile` for container specifics

---

**Branch**: `feature/cd-docker-deployment`
**Created**: January 2026
**Status**: Ready for review
