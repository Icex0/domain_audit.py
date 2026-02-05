# Domain Audit Tool - Dockerfile
# Multi-stage build for smaller final image

FROM python:3.11-slim AS builder

# Install git, build tools, Rust and UV
RUN apt-get update && apt-get install -y git gcc python3-dev curl && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN git config --global http.postBuffer 524288000
RUN pip install uv

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./
COPY src/ ./src/

# Install the package using UV
RUN uv pip install --system .

# Install external tools (certipy-ad and netexec)
RUN uv pip install --system certipy-ad git+https://github.com/Pennyw0rth/NetExec

# Final stage
FROM python:3.11-slim

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Set working directory for output
WORKDIR /data

# Entry point
ENTRYPOINT ["domain-audit"]
