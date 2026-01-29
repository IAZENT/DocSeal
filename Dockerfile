# Multi-stage Dockerfile for DocSeal
# Production-ready image with minimal size and GUI support

# Build stage
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Metadata
LABEL maintainer="DocSeal Team"
LABEL description="Secure academic document signing and verification tool with GUI"
LABEL version="2.0.0"
LABEL org.opencontainers.image.title="DocSeal"
LABEL org.opencontainers.image.description="PKI-based document signing and verification system"
LABEL org.opencontainers.image.vendor="DocSeal"

# Install GUI runtime dependencies and other system libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libdbus-1-3 \
    libfontconfig1 \
    libfreetype6 \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxkbcommon0 \
    libxkbcommon-x11-0 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r docseal && useradd -r -g docseal -u 1000 docseal && \
    mkdir -p /home/docseal/.docseal/ca && \
    chown -R docseal:docseal /home/docseal

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder --chown=docseal:docseal /root/.local /home/docseal/.local

# Copy application code
COPY src/ ./src/
COPY pyproject.toml ./

# Install the package
RUN pip install --no-cache-dir -e . && \
    chown -R docseal:docseal /app

# Set environment variables
ENV PATH=/home/docseal/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DOCSEAL_HOME=/home/docseal/.docseal

# Switch to non-root user
USER docseal

# Set home directory
ENV HOME=/home/docseal

# Keep container running with interactive bash shell
ENTRYPOINT ["/bin/bash"]
CMD ["-i"]
