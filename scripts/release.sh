#!/bin/bash
# Release script for DocSeal
# Usage: ./scripts/release.sh v0.2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if version argument provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: Version not provided${NC}"
    echo "Usage: $0 v0.2.0"
    exit 1
fi

VERSION=$1

# Validate version format
if ! [[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: Invalid version format. Use vX.Y.Z (e.g., v0.2.0)${NC}"
    exit 1
fi

echo -e "${YELLOW}🚀 DocSeal Release Script${NC}"
echo "Version: $VERSION"
echo ""

# Check if we're on main/master branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    echo -e "${RED}Error: You must be on main/master branch to release${NC}"
    echo "Current branch: $CURRENT_BRANCH"
    exit 1
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}Error: Working directory has uncommitted changes${NC}"
    git status
    exit 1
fi

echo -e "${YELLOW}Pre-release Checks${NC}"
echo "===================="

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
pytest tests/ -v --tb=short || {
    echo -e "${RED}Tests failed!${NC}"
    exit 1
}

# Run linting
echo -e "${YELLOW}Running linting...${NC}"
ruff check src/ || {
    echo -e "${RED}Linting failed!${NC}"
    exit 1
}

# Run type checks
echo -e "${YELLOW}Running type checks...${NC}"
mypy src/docseal || {
    echo -e "${RED}Type checks failed!${NC}"
    exit 1
}

echo -e "${GREEN}✓ All checks passed!${NC}"
echo ""

# Update version in pyproject.toml
echo -e "${YELLOW}Updating version in pyproject.toml...${NC}"
VERSION_NO_V=${VERSION#v}
sed -i "s/version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$VERSION_NO_V\"/" pyproject.toml
echo -e "${GREEN}✓ Updated to $VERSION_NO_V${NC}"

# Commit version update
echo -e "${YELLOW}Creating version commit...${NC}"
git add pyproject.toml
git commit -m "chore: bump version to $VERSION" || true

# Create tag
echo -e "${YELLOW}Creating tag $VERSION...${NC}"
git tag -a "$VERSION" -m "Release $VERSION

## Changes

This is the $VERSION release of DocSeal.

## Docker Image

ghcr.io/yourusername/docseal:$VERSION_NO_V

## Installation

### Docker
\`\`\`bash
docker pull ghcr.io/yourusername/docseal:$VERSION_NO_V
docker run --rm ghcr.io/yourusername/docseal:$VERSION_NO_V --help
\`\`\`

### Python
\`\`\`bash
pip install docseal==$VERSION_NO_V
\`\`\`
"

echo -e "${GREEN}✓ Tag created: $VERSION${NC}"
echo ""

# Instructions for user
echo -e "${YELLOW}Next Steps:${NC}"
echo "==========="
echo ""
echo "Review the changes:"
echo "  git log --oneline -5"
echo ""
echo "Push the tag to GitHub (this triggers the CD pipeline):"
echo "  ${GREEN}git push origin $VERSION${NC}"
echo ""
echo "Or push everything:"
echo "  ${GREEN}git push origin ${CURRENT_BRANCH} && git push origin $VERSION${NC}"
echo ""
echo "The CI/CD pipeline will:"
echo "  1. Run all tests"
echo "  2. Build Docker image"
echo "  3. Push to ghcr.io"
echo "  4. Publish to PyPI"
echo "  5. Create GitHub Release"
echo ""
echo -e "${YELLOW}Monitor the workflow:${NC}"
echo "  https://github.com/yourusername/docseal/actions"
echo ""
