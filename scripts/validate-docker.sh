#!/bin/bash
# Validate Docker setup for DocSeal
# This script checks if Docker files are properly configured

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Validating Docker setup...${NC}"
echo ""

ERRORS=0

# Check if Dockerfile exists
if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}✗ Dockerfile not found${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ Dockerfile exists${NC}"
    
    # Check for required instructions
    if grep -q "FROM python:3.11" Dockerfile; then
        echo -e "${GREEN}✓ Uses Python 3.11${NC}"
    else
        echo -e "${RED}✗ Dockerfile should use Python 3.11${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    if grep -q "USER docseal" Dockerfile; then
        echo -e "${GREEN}✓ Runs as non-root user${NC}"
    else
        echo -e "${RED}✗ Should run as non-root user${NC}"
        ERRORS=$((ERRORS + 1))
    fi
fi

# Check if Dockerfile.dev exists
if [ ! -f "Dockerfile.dev" ]; then
    echo -e "${RED}✗ Dockerfile.dev not found${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ Dockerfile.dev exists${NC}"
fi

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}✗ docker-compose.yml not found${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ docker-compose.yml exists${NC}"
    
    # Validate docker-compose syntax (if docker-compose is available)
    if command -v docker-compose &> /dev/null; then
        if docker-compose config > /dev/null 2>&1; then
            echo -e "${GREEN}✓ docker-compose.yml syntax is valid${NC}"
        else
            echo -e "${RED}✗ docker-compose.yml has syntax errors${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    fi
fi

# Check if .dockerignore exists
if [ ! -f ".dockerignore" ]; then
    echo -e "${YELLOW}⚠ .dockerignore not found (optional but recommended)${NC}"
else
    echo -e "${GREEN}✓ .dockerignore exists${NC}"
fi

# Check if GitHub workflows exist
if [ ! -d ".github/workflows" ]; then
    echo -e "${YELLOW}⚠ .github/workflows directory not found${NC}"
else
    if [ -f ".github/workflows/ci.yml" ]; then
        echo -e "${GREEN}✓ CI workflow exists${NC}"
    else
        echo -e "${YELLOW}⚠ CI workflow not found${NC}"
    fi
    
    if [ -f ".github/workflows/cd.yml" ]; then
        echo -e "${GREEN}✓ CD workflow exists${NC}"
    else
        echo -e "${YELLOW}⚠ CD workflow not found${NC}"
    fi
fi

# Check if required files exist
if [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}✗ pyproject.toml not found${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ pyproject.toml exists${NC}"
fi

if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}✗ requirements.txt not found${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ requirements.txt exists${NC}"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Build the image: docker build -t docseal:latest ."
    echo "  2. Test it: docker run --rm docseal:latest --help"
    echo "  3. Use docker-compose: docker-compose up -d docseal"
    exit 0
else
    echo -e "${RED}❌ Found $ERRORS error(s)${NC}"
    exit 1
fi

