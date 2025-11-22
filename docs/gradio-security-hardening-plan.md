# Purviewer Gradio Security Hardening Plan

**Created**: November 21, 2025
**Status**: Planning
**Target Version**: v0.6.1
**Priority**: High - Production deployment security

---

## Executive Summary

This plan addresses security hardening for the Gradio web interface before production deployment. It covers Docker containerization, network segmentation, file access controls, and ongoing patch management. The recommendations are based on known Gradio CVEs (SSRF, file traversal) and Docker security best practices.

**Reference**: Security analysis from GitHub discussion on Gradio deployment risks.

---

## Target Environment

**Host**: dh01.exactpartners.com (172.30.0.21)

| Setting | Value | Notes |
|---------|-------|-------|
| Docker Version | 28.2.2 | With Compose v2.36.2 |
| userns-remap | `dockremap:100000:65536` | Container UID 0 → Host 100000 |
| Storage | `/mnt/docker-storage` | 62GB available |
| Networks | `isolated-services`, `isolated-web`, `isolated-db` | Multi-tier isolation |
| Reverse Proxy | Caddy v2.10.2 | Already running, handles TLS |

### UID Mapping Reference

With userns-remap enabled:
- Container UID 0 → Host UID 100000
- Container UID 1000 → Host UID **101000**
- Formula: `Host UID = 100000 + Container UID`

---

## Risk Assessment

### Known Gradio Vulnerabilities

| CVE | Type | Fixed In | Risk to Purviewer |
|-----|------|----------|-------------------|
| CVE-2024-1183 | SSRF | 4.11.0 | Medium - could probe internal network |
| CVE-2024-47167 | SSRF | 4.44.0 | Medium - metadata endpoint access |
| File traversal | Path traversal | 4.11.0 | High - sign-in logs contain sensitive data |

### Purviewer-Specific Risks

1. **Sensitive data in uploads**: Entra ID sign-in logs contain:
   - User principal names (emails)
   - IP addresses and geolocations
   - Risk levels and authentication details
   - Device information

2. **Generated reports**: Analysis outputs to `/tmp/purviewer_*/`:
   - Markdown reports with compromise details
   - JSON reports with full anomaly data
   - CSV exports of all anomalies

3. **No shell execution**: Current code is safe (pandas/sklearn only)

---

## Implementation Plan

### Phase 1: Version Pinning and Dependencies

**Goal**: Lock Gradio to a known-secure version with controlled updates

#### 1.1 Pin Gradio Version

Update `pyproject.toml`:

```toml
dependencies = [
    # ... existing ...
    "gradio>=6.0.0,<6.1.0",  # Pin to specific minor version
]
```

**Rationale**:
- Prevents unexpected breaking changes
- Forces deliberate security review before updates
- Gradio 6.0+ has latest security fixes

#### 1.2 Create Requirements Lock

Generate locked requirements for Docker:

```bash
poetry export -f requirements.txt --output requirements.txt --without-hashes
```

---

### Phase 2: Dockerfile Creation

**Goal**: Minimal, non-root, hardened container

#### 2.1 Create Dockerfile

File: `Dockerfile`

```dockerfile
# Use minimal Python image
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
    rm -rf /root/.cache

# Copy application code
COPY --chown=purviewer:purviewer src/ ./src/
COPY --chown=purviewer:purviewer pyproject.toml README.md ./

# Install the application
RUN pip install --no-cache-dir -e . && \
    rm -rf /root/.cache

# Security: Switch to non-root user
USER purviewer

# Security: Set restrictive umask
ENV UMASK=0077

# Expose only the Gradio port
EXPOSE 7860

# Health check (curl not available in slim, use python)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/')" || exit 1

# Run the web interface
CMD ["python", "-m", "purviewer.main", "--web"]
```

**UID Mapping Note**: With userns-remap enabled on dh01, container UID 1000 maps to host UID 101000. Named volumes will automatically have correct ownership. For bind mounts, see ownership commands below.

#### 2.2 Create .dockerignore

File: `.dockerignore`

```
# Git
.git/
.gitignore

# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
.eggs/
dist/
build/
.mypy_cache/
.ruff_cache/

# Development
.venv/
venv/
*.md
!README.md
docs/
tests/
*.log

# IDE
.vscode/
.idea/

# Secrets (never include)
.env
*.key
*.pem
credentials.*

# Docker
Dockerfile
docker-compose*.yml
.dockerignore
```

---

### Phase 3: Environment Variables

**Goal**: Configure Gradio security settings via environment

#### 3.1 Security Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `GRADIO_SERVER_NAME` | `0.0.0.0` | Listen on all interfaces (container only) |
| `GRADIO_SERVER_PORT` | `7860` | Default port |
| `GRADIO_SHARE` | `False` | Disable public share links |
| `GRADIO_ANALYTICS_ENABLED` | `False` | Disable telemetry |
| `GRADIO_ALLOWED_PATHS` | `/data` | Only allow export directory |
| `GRADIO_BLOCKED_PATHS` | `/home,/root,/etc,/var,/proc,/sys` | Block sensitive paths |
| `GRADIO_ROOT_PATH` | (set by proxy) | URL path prefix if proxied |

#### 3.2 Create Environment File Template

File: `docker/.env.example`

```bash
# Gradio Security Settings
GRADIO_SERVER_NAME=0.0.0.0
GRADIO_SERVER_PORT=7860
GRADIO_SHARE=False
GRADIO_ANALYTICS_ENABLED=False

# File Access Restrictions
GRADIO_ALLOWED_PATHS=/data
GRADIO_BLOCKED_PATHS=/home,/root,/etc,/var,/proc,/sys,/tmp

# Proxy Integration (set if behind reverse proxy)
# GRADIO_ROOT_PATH=/purviewer
```

---

### Phase 4: Docker Compose Configuration

**Goal**: Production-ready container orchestration

#### 4.1 Create Docker Compose File

File: `docker/docker-compose.yml`

```yaml
version: '3.8'

services:
  purviewer:
    build:
      context: ..
      dockerfile: Dockerfile
    container_name: purviewer-web
    restart: unless-stopped

    # Security: Drop all capabilities
    cap_drop:
      - ALL

    # Security: Read-only root filesystem
    read_only: true

    # Security: No privilege escalation
    security_opt:
      - no-new-privileges:true

    # Writable directories (tmpfs for security)
    tmpfs:
      - /tmp:noexec,nosuid,size=512m

    # Persistent data volume (named volume - handles userns-remap automatically)
    volumes:
      - purviewer_data:/data

    # Environment variables
    env_file:
      - .env

    # Use existing isolated-services network (same as actual-budget, ejbca, caddy)
    networks:
      - isolated-services

    # Resource limits (fits within dh01's 4.1GB RAM)
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M

    # Health check
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:7860/')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

# Use existing external network
networks:
  isolated-services:
    external: true

# Named volume (automatically gets correct userns-remap ownership)
volumes:
  purviewer_data:
    driver: local
```

**Why Named Volumes**: Per your Docker reference doc, named volumes automatically handle userns-remap ownership. This avoids manual `chown 101000:101000` commands needed for bind mounts.

#### 4.2 Production Notes

**No port exposure needed**: Since Purviewer joins `isolated-services` (same network as Caddy), Caddy can reach it directly by container name. No host port binding required.

**Optional bind mount alternative**: If you prefer bind mounts for easier backup/inspection:

```yaml
# Alternative: bind mount instead of named volume
volumes:
  - /mnt/docker-storage/purviewer/data:/data
```

**Bind mount ownership** (required before first run):
```bash
# Create directory with correct ownership for userns-remap
sudo mkdir -p /mnt/docker-storage/purviewer/data
sudo chown -R 101000:101000 /mnt/docker-storage/purviewer/data
sudo chmod 755 /mnt/docker-storage/purviewer

# Verify
ls -ln /mnt/docker-storage/purviewer/data
# Should show: drwxr-xr-x 101000 101000
```

---

### Phase 5: Reverse Proxy Integration

**Goal**: Add site block to existing Caddy configuration

#### 5.1 Add Site Block to Existing Caddyfile

Your Caddy container is already running on dh01. Add this site block to your existing `/etc/caddy/Caddyfile`:

```caddyfile
# Add to existing Caddyfile (alongside actual-budget, etc.)

purviewer.yourdomain.com {
    # TLS handled automatically by Caddy (Let's Encrypt)

    # Basic authentication (minimum security)
    basicauth /* {
        # Generate hash: docker exec caddy caddy hash-password
        admin $2a$14$...hashed_password...
    }

    # Reverse proxy to Purviewer container (on isolated-services network)
    reverse_proxy purviewer-web:7860 {
        # WebSocket support for Gradio
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    # Security headers
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        X-XSS-Protection "1; mode=block"
        Referrer-Policy strict-origin-when-cross-origin
        -Server
    }
}
```

#### 5.2 Deployment Steps

```bash
# 1. Edit Caddyfile
docker exec -it caddy vi /etc/caddy/Caddyfile

# 2. Validate configuration
docker exec caddy caddy validate --config /etc/caddy/Caddyfile

# 3. Reload Caddy (no downtime)
docker exec caddy caddy reload --config /etc/caddy/Caddyfile

# 4. Generate password hash for basicauth
docker exec caddy caddy hash-password
# Enter password when prompted, copy hash to Caddyfile

# 5. Verify
curl -I https://purviewer.yourdomain.com
```

**Network Note**: Since both `caddy` and `purviewer-web` are on `isolated-services`, Caddy can reach Purviewer by container name without port exposure to host.

---

### Phase 6: Application Code Updates

**Goal**: Harden Gradio app configuration

#### 6.1 Update app.py Launch Configuration

```python
def launch_app(port: int = 7860, share: bool = False) -> None:
    """Launch the Gradio application.

    Args:
        port: Port to run the server on.
        share: Whether to create a public share link.
    """
    app = create_app()
    app.launch(
        server_port=port,
        share=share,
        show_error=True,
        # Security settings
        allowed_paths=["/data"],  # Minimal allowed paths
        blocked_paths=["/home", "/root", "/etc", "/var", "/proc", "/sys"],
        show_api=False,  # Disable API docs in production
    )
```

#### 6.2 Update Temp Directory Location

In `handlers.py`, use `/data` instead of system temp:

```python
import os

def __init__(self) -> None:
    """Initialize the analysis handler."""
    self.logger = PolyLog.get_logger(simple=True)
    # Use /data in container, fallback to temp for development
    data_dir = os.environ.get("PURVIEWER_DATA_DIR", "/data")
    if not os.path.exists(data_dir):
        data_dir = tempfile.mkdtemp(prefix="purviewer_")
    self._temp_dir = tempfile.mkdtemp(prefix="analysis_", dir=data_dir)
```

---

### Phase 7: Patch Management Process

**Goal**: Establish routine security update workflow

#### 7.1 Monitoring Setup

1. **Watch Gradio releases**:
   - GitHub: https://github.com/gradio-app/gradio/releases
   - Set "Watch → Releases only" and "Security advisories"

2. **NVD alerts**:
   - Subscribe to alerts for `gradio` package
   - https://nvd.nist.gov/

3. **Dependabot** (if using GitHub):
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "pip"
       directory: "/"
       schedule:
         interval: "weekly"
       labels:
         - "dependencies"
         - "security"
   ```

#### 7.2 Update Procedure

**Monthly routine** (or immediately for security releases):

```bash
# 1. Check current version
docker exec purviewer-web python -c "import gradio; print(gradio.__version__)"

# 2. Update version pin in pyproject.toml
# Edit: gradio>=6.0.0,<6.1.0 → gradio>=6.1.0,<6.2.0

# 3. Export new requirements
poetry export -f requirements.txt --output requirements.txt --without-hashes

# 4. Rebuild with fresh base image
docker compose -f docker/docker-compose.yml build --pull --no-cache

# 5. Deploy
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml up -d

# 6. Verify
docker exec purviewer-web python -c "import gradio; print(gradio.__version__)"
docker compose logs purviewer --tail=50
```

---

## File Structure

After implementation:

```
purviewer/
├── Dockerfile
├── .dockerignore
├── docker/
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── .env.example
│   └── Caddyfile.example
├── requirements.txt          # Locked dependencies
├── pyproject.toml           # Pinned versions
└── src/purviewer/web/
    ├── app.py               # Updated with security settings
    └── handlers.py          # Updated temp directory
```

---

## Implementation Checklist

### Phase 1: Version Pinning
- [ ] Pin Gradio version in pyproject.toml
- [ ] Generate requirements.txt lock file

### Phase 2: Dockerfile
- [ ] Create Dockerfile with non-root user
- [ ] Create .dockerignore
- [ ] Test local build

### Phase 3: Environment Variables
- [ ] Create .env.example template
- [ ] Document all security variables

### Phase 4: Docker Compose
- [ ] Create docker-compose.yml
- [ ] Create docker-compose.prod.yml
- [ ] Test container deployment

### Phase 5: Reverse Proxy
- [ ] Create Caddyfile.example
- [ ] Document integration steps

### Phase 6: Application Updates
- [ ] Update app.py with security settings
- [ ] Update handlers.py temp directory
- [ ] Test with restricted paths

### Phase 7: Patch Management
- [ ] Set up Dependabot or monitoring
- [ ] Document update procedure
- [ ] Schedule first security review

---

## Security Considerations Summary

| Layer | Control | Purpose |
|-------|---------|---------|
| Container | Non-root user | Limit privilege escalation |
| Container | Read-only filesystem | Prevent persistent malware |
| Container | Dropped capabilities | Minimize attack surface |
| Container | Resource limits | Prevent DoS |
| Network | Internal Docker network | Isolate from other services |
| Network | Localhost-only port | Require proxy for access |
| Application | Blocked paths | Prevent file traversal |
| Application | No share links | Prevent public exposure |
| Proxy | TLS termination | Encrypt traffic |
| Proxy | Authentication | Restrict access to staff |
| Process | Version pinning | Controlled updates |
| Process | Patch monitoring | Timely security fixes |

---

## Deployment Commands

### On dh01.exactpartners.com

```bash
# 1. Clone/copy purviewer to Docker host
cd /mnt/docker-storage
git clone https://github.com/ExactDoug/purviewer.git
cd purviewer

# 2. Build image
docker compose -f docker/docker-compose.yml build --pull

# 3. Deploy container
docker compose -f docker/docker-compose.yml up -d

# 4. Verify container is running
docker ps | grep purviewer
docker logs purviewer-web

# 5. Check health
docker inspect purviewer-web --format='{{.State.Health.Status}}'

# 6. Verify write permissions (per your reference doc)
docker exec -it purviewer-web sh -lc 'touch /data/_probe && ls -ln /data/_probe'
# Should show: -rw-r--r-- 1 1000 1000 ... /data/_probe

# 7. Add Caddy site block (see Phase 5)
docker exec -it caddy vi /etc/caddy/Caddyfile
docker exec caddy caddy reload --config /etc/caddy/Caddyfile

# 8. Test access
curl -I https://purviewer.yourdomain.com
```

### Useful Commands

```bash
# View real-time logs
docker logs -f purviewer-web

# Check resource usage
docker stats purviewer-web --no-stream

# Shell into container
docker exec -it purviewer-web /bin/bash

# Restart
docker compose -f docker/docker-compose.yml restart

# Stop and remove
docker compose -f docker/docker-compose.yml down

# Full rebuild (after updates)
docker compose -f docker/docker-compose.yml build --pull --no-cache
docker compose -f docker/docker-compose.yml up -d
```

### Troubleshooting

```bash
# Check container UID/GID
docker exec -it purviewer-web sh -lc 'id -u; id -g; whoami'
# Expected: 1000, 1000, purviewer

# Check mount flags
docker exec -it purviewer-web sh -lc 'grep " /data " /proc/mounts'
# Expect: rw, not ro

# Verify network connectivity to Caddy
docker exec purviewer-web ping -c 3 caddy
# Should succeed (both on isolated-services)

# Check Gradio version
docker exec purviewer-web python -c "import gradio; print(gradio.__version__)"
```

---

## Notes

- User will provide specific Caddy and network details for their environment
- VPN/identity proxy integration is handled by user's existing infrastructure
- This plan focuses on container and application hardening
- File access paths should be reviewed after deployment testing

---

**Next Action**: Implement Phase 1-2 (version pinning and Dockerfile) for initial testing.
