# FuzzForge Vertical Worker: Hash Cracking
#
ARG branch=pocl
FROM dizcza/docker-hashcat:$branch

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Build essentials for Atheris
    build-essential \
    clang \
    llvm \
    # Development tools
    git \
    curl \
    wget \
    unzip \
    python3 python3-pip \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*


RUN wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && unzip SecList.zip -d /usr/share/wordlists && rm -f SecList.zip

# Install Python dependencies for Temporal worker
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Create cache directory for downloaded targets
RUN mkdir -p /cache && chmod 755 /cache

# Copy worker entrypoint
COPY worker.py /app/worker.py

# Add toolbox and AI module to Python path (mounted at runtime)
ENV PYTHONPATH="/app:/app/toolbox:/app/ai_src:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

# Run worker
CMD ["python3", "/app/worker.py"]
