# Deployment Guide
## CyberGuard AI — Deployment Instructions

**Version:** 1.0  
**Date:** September 2026  
**Supported Platforms:** Ubuntu 20.04+, Debian 11+, Windows Server 2019+

---

## 1. Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB (2GB for agent + 2GB for OS) | 8 GB |
| **Disk** | 10 GB free | 50 GB (for log storage) |
| **OS (Agent)** | Ubuntu 20.04 / Windows Server 2019 | Ubuntu 22.04 / Windows Server 2022 |
| **OS (API Server)** | Ubuntu 20.04 / Docker | Ubuntu 22.04 / Docker |
| **Python** | 3.11+ | 3.11+ |
| **Network** | Agent can reach API Server port 8443 | Same |

### Required Software (API Server)

```bash
# Check versions
python3 --version    # Must be 3.11+
docker --version     # 24.0+ (if using Docker)
postgresql --version # 14+ (if using PostgreSQL for multi-device)
```

---

## 2. Installation: API Server

### Option A: Docker Compose (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/cyberguard-ai.git
cd cyberguard-ai

# 2. Copy and edit the environment file
cp .env.example .env
nano .env
```

**Edit `.env`:**
```env
# Security — CHANGE THESE IN PRODUCTION
SECRET_KEY=your-very-long-random-secret-key-change-this
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-this-secure-password
ADMIN_EMAIL=admin@yourcompany.com

# Database
DATABASE_URL=postgresql://cyberguard:password@db:5432/cyberguard

# TLS (provide your own certs or use Let's Encrypt)
TLS_CERT_PATH=/certs/fullchain.pem
TLS_KEY_PATH=/certs/privkey.pem

# Dashboard URL (for CORS)
DASHBOARD_URL=https://dashboard.yourcompany.com

# Agent registration token (admins use this to register new agents)
AGENT_REGISTRATION_TOKEN=change-this-registration-token
```

```bash
# 3. Start all services
docker compose up -d

# 4. Verify services are running
docker compose ps

# 5. Create the initial admin account
docker compose exec api python manage.py create_admin
```

**Verify installation:**
```bash
curl -k https://localhost:8443/api/v1/health
# Expected: {"status": "healthy", "version": "1.0.0"}
```

---

### Option B: Manual Installation (Linux)

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3-pip postgresql-14 redis-server

# 2. Create application user and directory
sudo useradd -r -s /bin/false cyberguard-server
sudo mkdir -p /opt/cyberguard-server
sudo chown cyberguard-server:cyberguard-server /opt/cyberguard-server

# 3. Install Python dependencies
cd /opt/cyberguard-server
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Set up PostgreSQL
sudo -u postgres psql -c "CREATE USER cyberguard WITH PASSWORD 'your-db-password';"
sudo -u postgres psql -c "CREATE DATABASE cyberguard OWNER cyberguard;"

# 5. Run database migrations
source venv/bin/activate
alembic upgrade head

# 6. Create systemd service
sudo nano /etc/systemd/system/cyberguard-api.service
```

**`/etc/systemd/system/cyberguard-api.service`:**
```ini
[Unit]
Description=CyberGuard AI API Server
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=cyberguard-server
WorkingDirectory=/opt/cyberguard-server
EnvironmentFile=/opt/cyberguard-server/.env
ExecStart=/opt/cyberguard-server/venv/bin/python -m uvicorn main:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-certfile /etc/ssl/certs/cyberguard.crt \
    --ssl-keyfile /etc/ssl/private/cyberguard.key
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# 7. Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable cyberguard-api
sudo systemctl start cyberguard-api
sudo systemctl status cyberguard-api
```

---

## 3. Installation: Dashboard (Frontend)

```bash
# 1. Navigate to dashboard directory
cd /opt/cyberguard-server/dashboard

# 2. Install Node.js dependencies
npm install

# 3. Build the production bundle
VITE_API_URL=https://api.yourcompany.com:8443 npm run build

# 4. Serve with nginx
sudo cp -r dist/ /var/www/cyberguard-dashboard/
```

**Nginx configuration (`/etc/nginx/sites-available/cyberguard`):**
```nginx
server {
    listen 443 ssl http2;
    server_name dashboard.yourcompany.com;

    ssl_certificate /etc/ssl/certs/cyberguard.crt;
    ssl_certificate_key /etc/ssl/private/cyberguard.key;
    ssl_protocols TLSv1.3;

    root /var/www/cyberguard-dashboard;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy WebSocket to API server
    location /ws {
        proxy_pass https://localhost:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

server {
    listen 80;
    server_name dashboard.yourcompany.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cyberguard /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## 4. Installation: Monitoring Agent

### Linux Agent

```bash
# 1. Download the agent installer
curl -fsSL https://api.yourcompany.com:8443/downloads/install-agent.sh | \
    sudo bash -s -- \
    --api-url https://api.yourcompany.com:8443 \
    --registration-token YOUR_REGISTRATION_TOKEN

# The script will:
# - Install the agent binary to /opt/cyberguard-agent/
# - Download the AI model (~150MB)
# - Create the cyberguard system user
# - Configure and start the systemd service
# - Register this device with the API server
```

**Verify agent installation:**
```bash
sudo systemctl status cyberguard-agent
sudo journalctl -u cyberguard-agent -f --since "1 minute ago"
```

**Expected log output:**
```
[CyberGuard Agent v1.0.0] Starting...
[CyberGuard Agent] AI model loaded: threat_model_v1.0.onnx (SHA256: abc123...)
[CyberGuard Agent] Connected to API server: https://api.yourcompany.com:8443
[CyberGuard Agent] Device registered: hostname=prod-server-01 id=device-uuid
[CyberGuard Agent] Scan cycle started. Monitoring 147 processes...
```

---

### Windows Server Agent

```powershell
# 1. Download installer (run as Administrator)
Invoke-WebRequest -Uri "https://api.yourcompany.com:8443/downloads/CyberGuardAgentInstaller.exe" `
    -OutFile "CyberGuardAgentInstaller.exe"

# 2. Run installer
.\CyberGuardAgentInstaller.exe `
    --api-url "https://api.yourcompany.com:8443" `
    --registration-token "YOUR_REGISTRATION_TOKEN" `
    --silent

# 3. Verify service is running
Get-Service -Name "CyberGuardAgent"
```

---

## 5. Configuration Reference

### Agent Configuration (`/etc/cyberguard/config.yaml`)

```yaml
agent:
  scan_interval_seconds: 5          # How often to scan processes (1-60)
  heartbeat_interval_seconds: 30    # How often to ping API server

api:
  url: "https://api.yourcompany.com:8443"
  api_key: "your-device-specific-api-key"    # Generated during registration
  tls_verify: true                            # Set to false only in dev

ai_engine:
  model_path: "/opt/cyberguard-agent/models/threat_model_v1.0.onnx"
  model_hash: "sha256:abc123..."              # Verified on load
  batch_size: 50                              # Processes per inference batch

threat_detection:
  suspicious_threshold: 0.3
  malicious_threshold: 0.7
  autonomous_kill_enabled: false
  autonomous_kill_threshold: 0.85

kill_protection:
  protected_pids: [1, 2]            # Always protect PID 1 (init) and PID 2 (kthreadd)
  protected_names:                   # Process names that can NEVER be killed
    - systemd
    - kernel
    - kworker
    - init

log_sources:
  - type: syslog
    path: /var/log/syslog
  - type: journald
    unit: "*"                        # Monitor all units
  - type: auth_log
    path: /var/log/auth.log

whitelist:
  auto_whitelist_signed: false       # Auto-whitelist verified signed processes

logging:
  level: INFO                        # DEBUG, INFO, WARNING, ERROR
  path: /var/log/cyberguard-agent.log
  max_size_mb: 100
  retention_days: 30
```

---

## 6. TLS Certificate Setup

### Let's Encrypt (Recommended for Public-Facing)

```bash
sudo apt-get install certbot
sudo certbot certonly --standalone -d api.yourcompany.com -d dashboard.yourcompany.com

# Certificates created at:
# /etc/letsencrypt/live/api.yourcompany.com/fullchain.pem
# /etc/letsencrypt/live/api.yourcompany.com/privkey.pem
```

### Self-Signed (For Internal/Air-Gapped Networks)

```bash
# Generate CA key and cert
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=CyberGuard Internal CA/O=YourOrg"

# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=api.internal/O=YourOrg"

# Sign the certificate
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# Add ca.crt to each agent machine's trust store
sudo cp ca.crt /usr/local/share/ca-certificates/cyberguard-ca.crt
sudo update-ca-certificates
```

---

## 7. Firewall Rules

```bash
# API Server — allow inbound
sudo ufw allow 8443/tcp comment "CyberGuard API Server"
sudo ufw allow 443/tcp comment "CyberGuard Dashboard (nginx)"

# Block direct access to database from outside
sudo ufw deny 5432/tcp
sudo ufw deny 6379/tcp

# Agent machines — allow outbound to API server only
sudo ufw allow out to {API_SERVER_IP} port 8443 proto tcp
```

---

## 8. Updating

### Update API Server (Docker)

```bash
cd /opt/cyberguard-server
git pull origin main
docker compose pull
docker compose up -d
docker compose exec api alembic upgrade head
```

### Update Agent (Linux)

```bash
# The agent can self-update when connected to the API server
sudo cyberguard-agent update --version 1.1.0

# Or manually
sudo systemctl stop cyberguard-agent
curl -fsSL https://api.yourcompany.com:8443/downloads/agent/linux/cyberguard-agent-1.1.0 \
    -o /opt/cyberguard-agent/cyberguard-agent
sudo systemctl start cyberguard-agent
```

---

## 9. Health Checks

```bash
# API Server health
curl -k https://localhost:8443/api/v1/health

# Agent status
sudo systemctl status cyberguard-agent

# Check agent logs
sudo journalctl -u cyberguard-agent --since "10 minutes ago"

# Database connectivity
docker compose exec api python -c "from db import engine; engine.connect(); print('DB OK')"

# Check number of connected agents
curl -H "Authorization: Bearer {token}" https://localhost:8443/api/v1/devices
```

---

## 10. Backup

### Database Backup

```bash
# Automated daily backup (add to cron)
pg_dump -U cyberguard cyberguard | gzip > /backups/cyberguard_$(date +%Y%m%d).sql.gz

# Retain 30 days
find /backups -name "cyberguard_*.sql.gz" -mtime +30 -delete
```

### Agent Config Backup

```bash
# Backup agent config and model
tar -czf /backups/agent-config-$(date +%Y%m%d).tar.gz \
    /etc/cyberguard/ \
    /opt/cyberguard-agent/models/
```

---

## 11. Troubleshooting

| Problem | Diagnosis | Fix |
|---|---|---|
| Agent won't connect | `journalctl -u cyberguard-agent` shows TLS error | Add server CA cert to agent's trust store |
| Agent showing as offline | Heartbeat not received in 90s | Check firewall rules, port 8443 open |
| AI model fails to load | Log shows hash mismatch | Re-download model: `cyberguard-agent update-model` |
| Dashboard shows no data | WebSocket connection refused | Check nginx WebSocket proxy config |
| High false positive rate | Many safe processes flagged SUSPICIOUS | Adjust `suspicious_threshold` to 0.5 in config |
| Agent using > 3% CPU | Profile with `py-spy` | Increase `scan_interval_seconds` to 10 |
| Kill action times out | Agent not responding | Check agent is running; restart if needed |

---

*End of Deployment Guide v1.0*
