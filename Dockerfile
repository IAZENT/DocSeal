# Multi-stage build for optimized image size
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Build the wheel
RUN pip install --upgrade pip setuptools wheel && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels .

# Final stage - production image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /app/wheels /wheels

# Copy documentation files from builder
COPY --from=builder /app/README.md /app/
COPY --from=builder /app/LICENSE /app/

# Install the package from wheels
RUN pip install --upgrade pip && \
    pip install --no-cache /wheels/* && \
    rm -rf /wheels

# Create a non-root user for security
RUN useradd -m -u 1000 docseal && \
    mkdir -p /home/docseal/data && \
    chown -R docseal:docseal /home/docseal

# Switch to non-root user
USER docseal
WORKDIR /home/docseal

# Set entrypoint to docseal CLI
ENTRYPOINT ["docseal"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD docseal --help > /dev/null || exit 1

# Labels for metadata
LABEL org.opencontainers.image.title="DocSeal" \
      org.opencontainers.image.description="Secure academic document signing and verification tool" \
      org.opencontainers.image.authors="Rupesh Thakur" \
      org.opencontainers.image.url="https://github.com/yourusername/docseal"
