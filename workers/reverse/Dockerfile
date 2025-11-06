# FuzzForge Vertical Worker: Reverse Engineering
#
# Pre-installed tools for Reverse engineering:
# - File carving tools (binwalk, unblob)
# - Binary analysis tools (capa)

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install flare-capa using pip and get capa-rules from GitHub
RUN <<EOF
set -eux -o pipefail

echo "Installing system dependencies..."
apt-get update && apt-get install -y build-essential clang llvm git curl wget
rm -rf /var/lib/apt/lists/*

echo "Installing flare-capa..."
pip install flare-capa --break-system-packages

echo "Fetching latest capa-rules version from GitHub..."
CAPA_RULES_VERSION=$(curl -sL https://api.github.com/repos/mandiant/capa-rules/releases/latest | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p')
CAPA_RULES_URL="https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_VERSION}.tar.gz"

echo "Creating rules directory..."
SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")
mkdir -p ${SITE_PACKAGES}/rules

echo "Downloading and installing capa rules version ${CAPA_RULES_VERSION}..."
curl -sL "${CAPA_RULES_URL}" | tar --strip-components 1 -C ${SITE_PACKAGES}/rules -xzvf -
EOF

#############################

# Install temporalIo worker dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --break-system-packages --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Create cache directory
RUN mkdir -p /cache && chmod 755 /cache

# Copy worker entrypoint (generic, works for all verticals)
COPY worker.py /app/worker.py

# Add toolbox to Python path (mounted at runtime)
ENV PYTHONPATH="/app:/app/toolbox:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

# Run worker
CMD ["python3", "/app/worker.py"]
