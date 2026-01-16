name: Release

on:
  push:
    tags:
      - "v*.*.*"

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

permissions:
  contents: write
  packages: write

jobs:
  test:
    name: Run Tests Before Release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .[dev]
      
      - name: Run tests
        env:
          PYTHONPATH: ./src
        run: |
          pytest tests/ -v

  build-package:
    name: Build Python Package
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      
      - name: Extract version from tag
        id: tag
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          echo "tag=v$VERSION" >> $GITHUB_OUTPUT
      
      - name: Update version in pyproject.toml
        run: |
          sed -i "s/version = \".*\"/version = \"${{ steps.tag.outputs.version }}\"/" pyproject.toml
      
      - name: Install build dependencies
        run: |
          python -m pip install --upgrade pip
          pip install build twine
      
      - name: Build package
        run: python -m build
      
      - name: Upload package artifacts
        uses: actions/upload-artifact@v3
        with:
          name: dist-package
          path: dist/*
          retention-days: 7

  publish-pypi:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    needs: build-package
    environment:
      name: pypi
      url: https://pypi.org/p/docseal
    steps:
      - uses: actions/checkout@v4
      
      - name: Extract version from tag
        id: tag
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          echo "version=$VERSION" >> $GITHUB_OUTPUT
      
      - name: Update version in pyproject.toml
        run: |
          sed -i "s/version = \".*\"/version = \"${{ steps.tag.outputs.version }}\"/" pyproject.toml
      
      - name: Install build dependencies
        run: |
          python -m pip install --upgrade pip
          pip install build twine
      
      - name: Build package
        run: python -m build
      
      - name: Publish to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*

  build-and-push-docker:
    name: Build and Push Docker Image
    runs-on: ubuntu-latest
    needs: test
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Extract version from tag
        id: tag
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          echo "tag=v$VERSION" >> $GITHUB_OUTPUT
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=tag
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=raw,value=latest
      
      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          platforms: linux/amd64,linux/arm64

  docker-test:
    name: Test Docker Image
    runs-on: ubuntu-latest
    needs: build-and-push-docker
    steps:
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract version from tag
        id: tag
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          echo "version=$VERSION" >> $GITHUB_OUTPUT
      
      - name: Test Docker image
        run: |
          docker pull ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.tag.outputs.version }}
          docker run --rm ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.tag.outputs.version }} --version
          docker run --rm ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.tag.outputs.version }} --help

  create-release:
    name: Create GitHub Release
    runs-on: ubuntu-latest
    needs: [build-package, build-and-push-docker]
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Download package artifacts
        uses: actions/download-artifact@v3
        with:
          name: dist-package
          path: dist/
      
      - name: Extract version from tag
        id: tag
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          echo "tag=v$VERSION" >> $GITHUB_OUTPUT
      
      - name: Generate changelog
        id: changelog
        run: |
          CHANGELOG=$(git log --pretty=format:"- %s (%h)" $(git describe --tags --abbrev=0 HEAD^)..HEAD 2>/dev/null || git log --pretty=format:"- %s (%h)" -10)
          echo "changelog<<EOF" >> $GITHUB_OUTPUT
          echo "$CHANGELOG" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT
      
      - name: Create Release
        uses: ncipollo/release-action@v1
        with:
          tag: ${{ steps.tag.outputs.tag }}
          name: Release ${{ steps.tag.outputs.tag }}
          body: |
            ## DocSeal ${{ steps.tag.outputs.version }}
            
            ### Changes
            ${{ steps.changelog.outputs.changelog }}
            
            ### Installation
            
            #### Docker
            ```bash
            docker pull ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.tag.outputs.version }}
            docker run --rm ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.tag.outputs.version }} --help
            ```
            
            #### PyPI
            ```bash
            pip install docseal==${{ steps.tag.outputs.version }}
            ```
            
            ### Docker Image
            - `${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.tag.outputs.version }}`
            - `${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest`
          files: dist/*
          draft: false
          prerelease: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
