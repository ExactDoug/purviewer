# Purviewer Gradio Web Interface
# Hardened Docker image for production deployment

FROM python:3.13-slim

# Security: Create non-root user with specific UID
# UID 1000 in container = UID 101000 on host (with userns-remap base 100000)
RUN groupadd -g 1000 purviewer && \
    useradd -m -u 1000 -g 1000 purviewer && \
    mkdir -p /app /data && \
    chown -R purviewer:purviewer /app /data

WORKDIR /app

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache /tmp/*

# Copy application code
COPY --chown=purviewer:purviewer src/ ./src/
COPY --chown=purviewer:purviewer pyproject.toml README.md ./

# Install the application
RUN pip install --no-cache-dir -e . && \
    rm -rf /root/.cache /tmp/*

# Security: Switch to non-root user
USER purviewer

# Security: Set restrictive umask
ENV UMASK=0077

# Gradio security defaults
ENV GRADIO_SERVER_NAME=0.0.0.0 \
    GRADIO_SERVER_PORT=7860 \
    GRADIO_SHARE=False \
    GRADIO_ANALYTICS_ENABLED=False

# Expose only the Gradio port
EXPOSE 7860

# Health check (curl not available in slim, use python)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/')" || exit 1

# Run the web interface
CMD ["python", "-m", "purviewer.main", "--web"]
