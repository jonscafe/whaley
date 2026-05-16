# 📖 Dedicated Docker Instancer - Documentation

Complete documentation for the CTF Docker Instancer.

## Table of Contents

- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Challenge Structure](#-challenge-structure)
- [API Reference](#-api-reference)
- [Authentication](#-authentication)
- [Admin Dashboard](#-admin-dashboard)
- [Dynamic Flags](#dynamic-flags)
- [Challenge Manager](#-challenge-manager)
- [Development](#-development)
- [Production Infrastructure](#-production-infrastructure)
- [Capacity Planning](#-capacity-planning--server-requirements)
- [Stress Testing](#-stress-testing)
- [Instance Forensics](#-instance-forensics-docker-log-capture)
- [Native Packet Capture](#-native-packet-capture)
- [Resource Monitoring](#-resource-monitoring)
- [Security](#-security)
- [Environment Variables](#-environment-variables)

---

## 📋 Prerequisites

- Docker & Docker Compose v2
- Python 3.11+ (for local development)
- A VPS with open port range (default: 20000-50000)

---

## 🚀 Installation

### 1. Clone and Configure

```bash
git clone https://github.com/jonscafe/whaley.git
cd whaley

# Copy and edit configuration
cp .env.example .env
nano .env
```

### 2. Configure Environment

Edit `.env` with your settings:

```env
# Authentication Mode: "ctfd" or "none"
AUTH_MODE=none

# For CTFd authentication
CTFD_URL=https://your-ctfd.com
CTFD_API_KEY=ctfd_admin_token_for_flags_and_sync

# Your VPS public IP or domain (use "auto" for auto-detection)
PUBLIC_HOST=auto

# Port range for instances
PORT_RANGE_START=20000
PORT_RANGE_END=50000

# Local admin dashboard key for AUTH_MODE=none (generate with: openssl rand -hex 32)
ADMIN_KEY=your-secure-admin-key
```

### 3. Add Your Challenges

Place challenges in the `challenges/` directory:

```
challenges/
├── your-challenge/
│   ├── challenge.yaml      # Challenge metadata
│   ├── docker-compose.yaml # Container definition
│   ├── Dockerfile          # Build instructions
│   └── ... (other files)
```

### 4. Start the Instancer

```bash
# Using Docker Compose (recommended)
docker compose up -d

# Or for development
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `none` | Authentication mode: `ctfd` or `none` |
| `CTFD_URL` | - | CTFd platform URL (required for ctfd mode) |
| `PUBLIC_HOST` | `localhost` | Public hostname/IP for instances. Use `auto` for auto-detection |
| `PORT_RANGE_START` | `20000` | Start of port range for instances |
| `PORT_RANGE_END` | `50000` | End of port range for instances |
| `INSTANCE_TIMEOUT` | `3600` | Default instance lifetime in seconds |
| `CHALLENGES_DIR` | `./challenges` | Directory containing challenge definitions |
| `ADMIN_KEY` | - | Local admin dashboard key used when `AUTH_MODE=none` |
| `CTFD_API_KEY` | - | CTFd admin API key for dynamic flags, sync wizard, and team-mode detection |
| `METRICS_SECRET` | - | Enables protected Prometheus `/metrics` endpoint when set |
| `FIREWALL_RATE_LIMIT_ENABLED` | `false` | Enable host-level per-instance connlimit/hashlimit rules on published ports |
| `FIREWALL_BACKEND` | `iptables` | Host firewall backend (`iptables` currently supported) |
| `FIREWALL_CHAIN` | `DOCKER-USER` | Firewall chain Whaley manages for published-port protection |
| `FIREWALL_CONN_LIMIT_PER_IP` | `60` | Max concurrent TCP connections per source IP per published port |
| `FIREWALL_RATE_PER_MINUTE` | `120` | Max new TCP connections per minute per source IP per published port |
| `FIREWALL_RATE_BURST` | `240` | Burst allowance for the per-IP new connection limit |
| `FIREWALL_REJECT_MODE` | `reject` | `reject` sends TCP reset; `drop` silently discards |
| `FIREWALL_STRICT` | `false` | Fail spawn if firewall rule apply fails instead of running degraded |
| `FIREWALL_USE_NSENTER` | `false` | Run firewall commands via `nsenter -t 1 -n` to reach host netns |
| `DYNAMIC_FLAGS_ENABLED` | `false` | Enable per-user dynamic flags |
| `FLAG_PREFIX` | `FLAG` | Prefix for generated flags (e.g., `FLAG{...}`) |
| `PCAP_ENABLED` | `true` | Enable tcpdump sidecars for new instance spawns |
| `PCAP_MODE` | `all` | Packet-capture policy: `all`, `selected`, or `none` |
| `PCAP_SELECTED_CHALLENGES` | - | Comma-separated challenge IDs used when `PCAP_MODE=selected` |
| `PCAP_MAX_SIZE_MB` | `25` | Rotate PCAP files after they reach this size |
| `PCAP_RETENTION_HOURS` | `24` | Automatically delete old captures after this many hours |
| `PCAP_SNAP_LEN` | `1024` | Capture snap length in bytes |
| `PCAP_BPF_FILTER` | `not (host 127.0.0.11 and port 53)` | Default filter that trims Docker DNS noise |
| `LOG_FILE` | `logs/events.jsonl` | Path to event log file |
| `DEBUG` | `false` | Enable debug mode |
| `ADMIN_RATE_LIMIT` | `150` | Admin API requests allowed per minute per client IP |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated proxy IPs/CIDRs allowed to supply `X-Forwarded-For`/`X-Real-IP` |

### VPS Firewall Setup

```bash
# Allow instancer API
sudo ufw allow 8000/tcp

# Allow instance port range
sudo ufw allow 20000:50000/tcp
```

---

## 📁 Challenge Structure

### challenge.yaml

```yaml
id: my-web-challenge
name: "My Web Challenge"
category: web  # web, pwn, rev, crypto, misc, forensics
description: "A cool web challenge"
ports:
  - 80        # Internal ports to expose
timeout: 3600 # Instance lifetime in seconds
```

### Multi-Port Challenge Example

```yaml
id: safe-social
name: "Safe Social"
category: web
description: "A social media platform challenge with XSS bot"
ports:
  - 5173   # Frontend
  - 10003  # Backend API
timeout: 3600
```

### docker-compose.yaml

> **Note:** Both `docker-compose.yaml` and `docker-compose.yml` are supported.

#### Single Service Example

```yaml
services:
  web:
    build: .
    ports:
      - "${PORT_80:-8080}:80"  # Use PORT_<internal> env var
    environment:
      - FLAG=CTF{your_flag}
    mem_limit: 128m
    cpus: 0.5
```

#### Multi-Service Example

```yaml
services:
  backend:
    build: ./backend
    ports:
      - "${PORT_10003:-10003}:10003"
    environment:
      - FLASK_ENV=production
    mem_limit: 256m
    cpus: 0.5

  frontend:
    build: ./frontend
    ports:
      - "${PORT_5173:-5173}:5173"
    depends_on: [backend]
    mem_limit: 256m
    cpus: 0.5

  bot:
    build: ./bot
    depends_on: [backend, frontend]
    environment:
      - API_BASE=http://backend:10003
      - FRONTEND_BASE=http://frontend:5173
    mem_limit: 512m
    cpus: 0.5
```

> **Important:** Do NOT use `container_name` in your docker-compose as it prevents multiple instances from running simultaneously.

Whaley starts each instance from a per-instance copy of the challenge directory. This keeps dynamic flag injection, resource-limit rewrites, and bind-mounted challenge files stable until the instance is stopped.

Whaley also validates compose files before startup and rejects options that would bypass isolation, including `privileged`, `network_mode`, host/container namespaces, added capabilities/devices, unsafe security options, Docker socket mounts, external networks/volumes, unsafe build or env-file paths, absolute/home/environment-expanded bind sources, and bind paths containing `..`. The hardening-safe `security_opt: ["no-new-privileges:true"]` option is allowed.

### Tips for Challenge Authors

- **No `container_name`** - Don't use container_name to allow multiple instances
- **Use PORT env vars** - Always use `${PORT_<internal>}` for exposed ports
- **Set resource limits** - Add `mem_limit` and `cpus` to prevent abuse
- **Multi-port challenges** - List all ports in challenge.yaml that users need to access
- **Internal services** - Services like bots that don't need external access don't need port mappings
- **Keep binds local** - Use relative paths inside the challenge directory if a service needs files from the repository

---

## 🔌 API Reference

### Health & Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI (user interface) |
| `/api` | GET | API info |
| `/health` | GET | Detailed health status |
| `/metrics` | GET | Prometheus metrics when `METRICS_SECRET` is configured |

### Challenges

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenges` | GET | List available challenges |
| `/challenges/{id}` | GET | Get challenge details |

### Instances

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/instances` | GET | List user's instances |
| `/instances/spawn` | POST | Spawn new instance |
| `/instances/{id}` | GET | Get instance details |
| `/instances/{id}` | DELETE | Stop instance |
| `/instances/{id}/extend` | POST | Extend instance lifetime |

### User

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/me` | GET | Get current user info |

### Admin API Authentication

Admin API auth depends on `AUTH_MODE`:

- `AUTH_MODE=ctfd`: send `Authorization: Bearer <CTFd access token>`. Whaley validates the token via CTFd and requires the CTFd user `type` to be `admin`.
- `AUTH_MODE=none`: send `X-Admin-Key: <ADMIN_KEY>`.

All admin endpoints are also rate-limited by client IP using `ADMIN_RATE_LIMIT`.

### Admin (requires admin auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin` | GET | Admin dashboard UI |
| `/admin/api/me` | GET | Verify admin auth and return the authenticated admin user |
| `/admin/api/stats` | GET | Get system statistics |
| `/admin/api/instances` | GET | List all active instances |
| `/admin/api/instances/spawn` | POST | Manually spawn an instance for a user/team owner |
| `/admin/api/instances/{id}` | GET | Get one instance with admin metadata |
| `/admin/api/instances/{id}` | DELETE | Force-stop/destroy an instance |
| `/admin/api/instances/{id}/logs` | GET | Get live Docker logs for an instance |
| `/admin/api/instances/{id}/metrics` | GET | Get live per-instance resource metrics |
| `/admin/api/monitoring/system` | GET | Get host snapshot and optional aggregate container stats |
| `/admin/api/monitoring/instances` | GET | Get paginated instance inventory; Docker metrics are opt-in per page |
| `/admin/api/firewall/status` | GET | Get global host firewall/rate-limit status |
| `/admin/api/firewall/instances/{id}` | GET | Get tracked firewall rules for one instance |
| `/admin/api/firewall/cleanup` | POST | Remove stale tracked firewall rules for dead instances |
| `/admin/api/firewall/reapply/{id}` | POST | Re-apply firewall rules for one active instance |
| `/admin/api/logs` | GET | Get event logs (with filtering) |

### Packet Capture (requires admin auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/api/pcap/status` | GET | Get capture status, parser availability, and storage totals |
| `/admin/api/pcap/policy` | GET | Get packet-capture mode and selected challenges |
| `/admin/api/pcap/policy` | PUT | Update packet-capture mode and selected challenges |
| `/admin/api/pcap/toggle` | POST | Enable or disable packet capture for new spawns |
| `/admin/api/pcap/instances` | GET | List instances that have capture files |
| `/admin/api/pcap/instances/{id}/summary` | GET | Get parsed summary for one instance |
| `/admin/api/pcap/instances/{id}/flows` | GET | List parsed flows with protocol and flag filters |
| `/admin/api/pcap/instances/{id}/flows/{flow_id}` | GET | Get packet-by-packet detail for one flow |
| `/admin/api/pcap/instances/{id}/flows/{flow_id}/payload` | GET | Get follow-stream style payload output |
| `/admin/api/pcap/instances/{id}/search` | GET | Search flow payloads for text or hex content |
| `/admin/api/pcap/instances/{id}/download` | GET | Download raw `.pcap` files for one instance |
| `/admin/api/pcap/cleanup` | POST | Delete capture directories older than retention |

### Challenge Management (requires admin auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/api/challenges/list` | GET | List all challenges with load status |
| `/admin/api/challenges/upload` | POST | Upload a zipped challenge |
| `/admin/api/challenges/{id}` | DELETE | Delete a challenge directory |
| `/admin/api/challenges/{id}/files` | GET | List all files in a challenge |
| `/admin/api/challenges/{id}/files/{path}` | GET | Read file content |
| `/admin/api/challenges/{id}/files/{path}` | PUT | Write/update file content |
| `/admin/api/challenges/{id}/files/{path}` | DELETE | Delete a file |
| `/admin/api/challenges/{id}/reload` | POST | Reload challenge configuration |

### Dynamic Flags / Anti-Cheat (requires admin auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/api/flags` | GET | Get all flag mappings and suspicious submissions |
| `/admin/api/flags/check-submissions` | POST | Scan CTFd for suspicious submissions |
| `/admin/api/flags/suspicious` | DELETE | Clear suspicious submissions list |
| `/admin/api/flags/sync-challenge` | POST | Map local challenge to CTFd challenge ID |
| `/admin/api/flags/mapping/{id}` | DELETE | Remove a challenge mapping |
| `/admin/api/flags/user/{user_id}` | DELETE | Delete all flags for a user |
| `/admin/api/flags/{flag_id}` | DELETE | Delete a specific flag mapping |
| `/admin/api/ctfd/challenges` | GET | Fetch CTFd challenges with mapping suggestions |

### Prometheus Metrics

Whaley exposes a Prometheus-compatible `/metrics` endpoint when `METRICS_SECRET` is configured. The endpoint is disabled with HTTP 503 when the secret is empty.

Authenticate with either header:

```bash
curl -H "Authorization: Bearer $METRICS_SECRET" \
  http://localhost:8000/metrics

curl -H "X-Metrics-Secret: $METRICS_SECRET" \
  http://localhost:8000/metrics
```

The exposition includes instance counts by status/owner/team/challenge, per-instance age and expiry gauges, port pool usage, loaded/active challenge counts, dynamic flag counts, suspicious submission totals, forensics storage totals, packet-capture storage totals, and event log counters.

### Admin Instance Operations

Manual spawn request:

```bash
curl -X POST "http://localhost:8000/admin/api/instances/spawn" \
  -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "example-web",
    "user_id": "admin-manual",
    "username": "admin"
  }'
```

Team-owner spawn request:

```bash
curl -X POST "http://localhost:8000/admin/api/instances/spawn" \
  -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "example-web",
    "user_id": "42",
    "username": "alice",
    "team_id": "7",
    "team_name": "Blue Team",
    "team_mode": true
  }'
```

Inspect and destroy:

```bash
# Instance metadata and status
curl -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/instances/{instance_id}"

# Live Docker logs, combined across containers
curl -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/instances/{instance_id}/logs?tail=300"

# Live CPU/RAM/network/block IO/PID metrics
curl -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/instances/{instance_id}/metrics"

# Force-stop/destroy
curl -X DELETE -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/instances/{instance_id}"
```

Failed admin spawn/stop operations return HTTP 400/404 with the backend error message in `detail`, so the dashboard can show Docker, compose, port allocation, and cleanup failures directly.

#### CTFd Sync Wizard API

```bash
# Fetch all CTFd challenges with mapping info
curl -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/ctfd/challenges"

# Filter by search term
curl -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/ctfd/challenges?search=web"

# Filter by category
curl -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
  "http://localhost:8000/admin/api/ctfd/challenges?category=Web"
```

If `AUTH_MODE=none`, replace the header above with `X-Admin-Key: <ADMIN_KEY>`.

Response:
```json
{
  "success": true,
  "challenges": [
    {
      "id": 42,
      "name": "Basic Web",
      "category": "Web",
      "value": 100,
      "type": "standard",
      "mapped_local_id": null,
      "suggested_local_id": "basic-web",
      "name_match_score": 100
    }
  ],
  "categories": ["Web", "Pwn", "Crypto"],
  "total": 15
}
```

### API Usage Examples

#### List Available Challenges

```bash
curl http://localhost:8000/challenges
```

Response:
```json
{
  "challenges": [
    {
      "id": "example-web",
      "name": "Example Web Challenge",
      "category": "web",
      "description": "A simple web exploitation challenge",
      "ports": [80]
    }
  ]
}
```

#### Spawn an Instance

```bash
curl -X POST http://localhost:8000/instances/spawn \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": "example-web"}'
```

Response (single port):
```json
{
  "success": true,
  "message": "Instance started successfully",
  "instance": {
    "instance_id": "example-web-abc123-def456",
    "challenge_id": "example-web",
    "status": "running",
    "ports": {"80": 31234},
    "public_url": "your-vps:31234",
    "public_urls": {"80": "your-vps:31234"},
    "expires_at": "2026-01-02T12:00:00+00:00"
  }
}
```

Response (multi-port challenge):
```json
{
  "success": true,
  "message": "Instance started successfully",
  "instance": {
    "instance_id": "safe-social-abc123-def456",
    "challenge_id": "safe-social",
    "status": "running",
    "ports": {"5173": 32001, "10003": 32002},
    "public_url": "your-vps:32001",
    "public_urls": {
      "5173": "your-vps:32001",
      "10003": "your-vps:32002"
    },
    "expires_at": "2026-01-02T12:00:00+00:00"
  }
}
```

#### Stop an Instance

```bash
curl -X DELETE http://localhost:8000/instances/example-web-abc123-def456
```

#### Extend Instance Lifetime

```bash
curl -X POST http://localhost:8000/instances/example-web-abc123-def456/extend
```

---

## 🔐 Authentication

### CTFd Mode

Users authenticate with their CTFd access token. Whaley accepts the token as a bearer token, validates it against CTFd's API (`/api/v1/users/me`), then fetches the detailed user record from `/api/v1/users/{id}`.

**Via API:**
```bash
curl -H "Authorization: Bearer YOUR_CTFD_TOKEN" \
  http://your-instancer:8000/challenges
```

**Via Web UI:**
1. Open `http://your-instancer:8000/` in browser
2. Enter your CTFd access token when prompted
3. Token is saved in browser `sessionStorage` and clears when the tab/session closes

To get a CTFd token, users go to CTFd → Settings → Access Tokens.

### Admin RBAC in CTFd Mode

The admin dashboard uses the same CTFd access-token flow as the user dashboard, but Whaley additionally checks the CTFd user role:

1. The browser sends `Authorization: Bearer <token>` to `/admin/api/me`.
2. Whaley calls CTFd `/api/v1/users/me` with that token and reads the authenticated user's `id`.
3. Whaley calls CTFd `/api/v1/users/{id}` with the same token.
4. Admin access is granted only when that detailed CTFd user response has `type: "admin"`.

Regular CTFd users can still use the challenge dashboard, but admin endpoints return HTTP 403. The user dashboard shows the **Admin Panel** link only when the authenticated CTFd user is an admin.

### No Auth Mode

Users are identified by IP address. No authentication required:

```bash
curl http://your-instancer:8000/challenges
```

In no-auth mode, admin endpoints require the local `ADMIN_KEY` via `X-Admin-Key`. If Whaley is behind a reverse proxy, set `TRUSTED_PROXIES` to the proxy IPs or CIDRs; otherwise forwarded IP headers are ignored to prevent IP spoofing.

---

## 📊 Admin Dashboard

Access the admin dashboard at `http://your-instancer:8000/admin`

Authentication follows the admin API rules:

- In CTFd mode, enter a CTFd access token from an admin user.
- In no-auth mode, enter the local `ADMIN_KEY` configured for Whaley.

The admin dashboard has these tabs:

### 1. Dashboard
- 📈 **Statistics** - Total spawns, active instances, unique users, and instance status counts
- 🛠️ **Manual Instance Control** - Spawn a challenge as a chosen user or team owner
- 🖥️ **Active Instances** - View all running/starting/error instances with force-stop capability
- 📜 **Per-Instance Logs** - Open live Docker logs from the instance card
- 📈 **Per-Instance Metrics** - Inspect CPU, RAM, network I/O, block I/O, and PID usage

### 2. Event Logs
- 📋 **Filterable Logs** - Filter by event type, username, limit
- Shows all spawn, stop, extend, and expiry events with Docker error details

### 3. Dynamic Flags
- 🚩 **Status Overview** - View enabled status, total flags, suspicious count
- ⚠️ **Suspicious Submissions** - List of users who submitted other users' flags
- 🔐 **Flag Mappings** - View all user-flag assignments
- 🗺️ **Challenge ID Mapping** - Map local challenges to CTFd challenge IDs

### 4. Challenge Manager
- 📤 **Upload Challenges** - Upload .zip files containing challenges
- 📁 **File Browser** - Browse and edit challenge files
- 🔄 **Reload Config** - Apply changes to challenge.yaml

### 5. Packet Capture
- 📡 **Capture Status** - Toggle packet capture for future spawns and track storage usage
- 📚 **Paginated Capture List** - Browse many captured instances without parsing every PCAP at tab load
- 🔎 **Flow Explorer** - Filter/search flows by protocol, flag tags, and payload content
- 💾 **Raw PCAP Download** - Export rotated `.pcap` files for offline Wireshark analysis
- 🧹 **Retention Cleanup** - Manually prune captures older than the configured retention window

### 6. Monitoring
- 🔍 **Host Snapshot** - View host load, memory, disk usage, and tracked container counts without sweeping Docker stats
- 📦 **Per-Instance Inventory** - Browse paginated active instances without freezing the dashboard
- 🎯 **Sample Page Metrics** - Collect Docker CPU/RAM only for the current monitoring page when you need detail
- 🛡 **Firewall Status** - Inspect connlimit/hashlimit policy, stale rule count, and per-instance rule state
- 📡 **Prometheus Export** - Use `/metrics` with `METRICS_SECRET` for external scraping

### 7. Settings
- ⚙️ **Live Settings** - Update editable Whaley settings without restarting the service

Admin actions surface backend error messages in the UI. If a manual spawn fails because compose build failed, no ports are available, Docker is unreachable, firewall rule apply fails, or cleanup only partially succeeded, the dashboard shows the returned reason instead of a generic failure toast.

**Log Format (JSONL):**
```json
{"timestamp": "2026-01-02T10:30:00+00:00", "event": "instance_spawn", "user": "user123", "challenge_id": "safe-social", "instance_id": "safe-social-abc123", "ports": {"5173": 32001, "10003": 32002}, "public_url": "vps:32001"}
{"timestamp": "2026-01-02T10:35:00+00:00", "event": "instance_spawn_failed", "user": "user456", "challenge_id": "broken-chall", "details": {"reason": "Failed to start instance", "docker_error": "error building image..."}}
```

---

## 📂 Challenge Manager

The admin dashboard includes a **Challenge Manager** that allows you to upload and edit challenges directly from the web interface—no SSH/VPS access required!

### Features

- **📤 Upload Challenges** - Upload a `.zip` file containing your challenge
- **📁 File Browser** - Browse all files in a challenge directory
- **✏️ Built-in Editor** - Edit text files directly in the browser
- **➕ Create Files** - Create new files within a challenge
- **🗑️ Delete Files** - Remove files or entire challenges
- **🔄 Reload Config** - Reload challenge.yaml after making changes

### How to Use

1. Open the admin dashboard: `http://your-instancer:8000/admin#challenges`
2. Click the **Challenge Manager** tab
3. To add a new challenge:
   - Click the upload zone or drag & drop a `.zip` file
   - The zip should contain a folder with your challenge files
   - Example structure:
     ```
     my-challenge.zip
     └── my-challenge/
         ├── challenge.yaml
         ├── docker-compose.yaml
         ├── Dockerfile
         └── src/
             └── app.py
     ```
4. After upload, click **Edit Files** to browse and modify files
5. After editing `challenge.yaml`, click **Reload** to apply changes

### Security

- Zip uploads reject path traversal, absolute paths, Windows absolute paths, and symlinks
- All file operations are protected with path traversal checks and stay inside `./challenges/`
- Binary files are marked as non-editable; writes are limited to text files up to 2 MB
- Challenge IDs may come from `challenge.yaml` and can differ from folder names; the manager resolves both safely
- Challenge deletion is blocked while active instances are still using the challenge
- Runtime spawns also reject challenge source trees that contain symlinks

---

## 🛠️ Development

### Local Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run in development mode
DEBUG=true python -m uvicorn app.main:app --reload
```

### Project Structure

```
whaley/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Settings & configuration
│   ├── models.py            # Pydantic models
│   ├── auth.py              # Authentication handlers
│   ├── docker_manager.py    # Docker/compose management
│   ├── docker_client.py     # Docker SDK wrapper
│   ├── port_manager.py      # Port allocation
│   ├── flag_manager.py      # Dynamic flags and suspicious submissions
│   ├── forensics.py         # Instance log capture
│   ├── monitoring.py        # Container/system metrics
│   ├── logger.py            # Event logging
│   ├── distributed_lock.py  # Redis-based distributed locking
│   ├── database/            # Database layer
│   │   ├── __init__.py
│   │   ├── models.py        # SQLAlchemy ORM models
│   │   └── connection.py    # Async database connection
│   └── static/              # Web UI files
│       ├── index.html       # User interface
│       ├── admin.html       # Admin dashboard
│       ├── style.css
│       └── app.js
├── challenges/              # Challenge definitions
├── data/                    # SQLite database (auto-created)
├── logs/                    # Event logs
├── docker-compose.yaml      # Instancer deployment
├── Dockerfile
├── requirements.txt
└── README.md
```

### Creating New Challenges

1. Create a new folder in `challenges/`
2. Add `challenge.yaml` with metadata
3. Add `docker-compose.yaml` (or `.yml`) with service definition
4. Add `Dockerfile` and challenge files
5. Test locally: `docker compose up --build`
6. Restart instancer to load new challenges

---

## 🏗️ Production Infrastructure

Whaley includes production-ready infrastructure components for reliable, scalable deployments.

### Architecture Overview

```
┌───────────────────────────────────────────┐
│           Whaley Instancer                 │
├───────────────────────────────────────────┤
│  FastAPI  │  Docker Manager  │  Port Mgr   │
└────┬─────┴────────┬─────────┴──────┬──────┘
       │               │              │
       ▼               ▼              ▼
┌──────────┐  ┌────────────┐  ┌─────────────┐
│ SQLite/  │  │   Redis    │  │   Docker    │
│ Postgres │  │   Locks    │  │   Engine    │
└──────────┘  └────────────┘  └─────┬───────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              ┌─────────┐  ┌─────────┐  ┌─────────┐
              │net-inst1│  │net-inst2│  │net-inst3│
              │[isolated]│  │[isolated]│  │[isolated]│
              └─────────┘  └─────────┘  └─────────┘
```

### Components

#### 1. Database (SQLite/PostgreSQL)

Persistent storage for port mappings, event logs, and instance state.

| Feature | SQLite (Default) | PostgreSQL |
|---------|------------------|------------|
| Setup | Zero config | Requires server |
| Scaling | Single worker | Multi-worker |
| Use Case | Development, small events | Production, large events |

**Configuration:**
```env
# SQLite (default - auto-created in /app/data/)
DATABASE_URL=sqlite+aiosqlite:///./data/whaley.db

# PostgreSQL (for production)
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/whaley
```

#### 2. Distributed Locking (Redis)

Prevents race conditions when running multiple Gunicorn workers. Spawn checks, persistent port assignment, and Docker Compose startup are protected by locks; with Redis enabled, Whaley holds a distributed port-allocation lock until compose startup has bound the selected ports.

Spawn, stop, and extend operations also use per-instance lifecycle locks. This prevents a stop request from racing with a still-starting compose project, and prevents concurrent stop/extend requests from mutating the same instance state at the same time.

| Without Redis | With Redis |
|---------------|------------|
| Single worker only | Multi-worker safe |
| asyncio.Lock() | Redis SETNX locks |
| Memory-based | Distributed |

**Configuration:**
```env
# Redis URL (optional - falls back to local locks if not set)
REDIS_URL=redis://redis:6379/0
```

> ⚠️ **Important**: Without Redis, only run with 1 worker (`uvicorn` or `gunicorn -w 1`)

#### 3. Docker SDK

Native Docker API integration using `docker-py` library.

**Benefits:**
- ✅ Docker SDK for container, network, image, stats, and log operations
- ✅ Better error handling with typed exceptions
- ✅ Native container/network lifecycle management
- ✅ Proper resource cleanup for containers, networks, volumes, and per-spawn images

Whaley labels compose services and creates isolated networks with ownership metadata. On startup and during periodic cleanup, it removes stale Whaley compose projects, orphan networks, dangling volumes, and per-spawn build images while preserving currently tracked active projects.

#### 4. Network Isolation

Each instance runs in its own isolated Docker bridge network.

**Features:**
- 🔒 Instances cannot communicate with each other
- 🛡️ Prevents lateral movement attacks between challenges
- 🧪 Automatic network cleanup on instance termination
- 🧱 Compose files are attached to the per-instance external network automatically
- 🌐 Compose-defined challenge networks receive explicit Whaley-managed subnets

**Configuration:**
```env
# Enable network isolation (recommended)
NETWORK_ISOLATION_ENABLED=true

# Disable inter-container communication
NETWORK_ICC_DISABLED=true

# Network name prefix
NETWORK_PREFIX=whaley

# Address pool used for Whaley isolation networks and compose-created challenge networks
NETWORK_SUBNET_BASE=10.240.0.0/16
NETWORK_SUBNET_PREFIX=28
```

### Deployment Modes

#### Development (Default)
```yaml
# docker-compose.yaml
services:
  instancer:
    # SQLite + local locks, no Redis needed
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/whaley.db
```

#### Production (Multi-Worker)
```yaml
# docker-compose.yaml
services:
  redis:
    image: redis:7-alpine
    
  instancer:
    depends_on: [redis]
    environment:
      - DATABASE_URL=postgresql+asyncpg://...
      - REDIS_URL=redis://redis:6379/0
    command: gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
```

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | SQLite auto | Database connection string |
| `DATA_DIR` | `/app/data` | Directory for SQLite database |
| `REDIS_URL` | - | Redis connection URL (optional) |
| `NETWORK_ISOLATION_ENABLED` | `true` | Create isolated network per instance |
| `NETWORK_ICC_DISABLED` | `true` | Disable inter-container communication |
| `NETWORK_PREFIX` | `whaley` | Prefix for instance networks |
| `NETWORK_SUBNET_BASE` | `10.240.0.0/16` | Whaley-managed address pool for per-instance isolation networks and compose-created challenge networks |
| `NETWORK_SUBNET_PREFIX` | `28` | Prefix length allocated from `NETWORK_SUBNET_BASE` for each Docker bridge network |
| `ADMIN_RATE_LIMIT` | `150` | Admin API requests allowed per minute per client IP |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Trusted reverse proxies for forwarded client IP headers |
| `METRICS_SECRET` | - | Secret required for Prometheus `/metrics`; empty disables endpoint |
| `FIREWALL_RATE_LIMIT_ENABLED` | `false` | Enable host-level per-instance connlimit/hashlimit rules |
| `FIREWALL_BACKEND` | `iptables` | Firewall backend managed by Whaley |
| `FIREWALL_CHAIN` | `DOCKER-USER` | Chain used for challenge published-port protection |
| `FIREWALL_CONN_LIMIT_PER_IP` | `60` | Max concurrent TCP connections per source IP per published port |
| `FIREWALL_RATE_PER_MINUTE` | `120` | Max new TCP connections per minute per source IP per published port |
| `FIREWALL_RATE_BURST` | `240` | Burst allowance for the new connection limiter |
| `FIREWALL_REJECT_MODE` | `reject` | Reject with TCP reset or silently drop |
| `FIREWALL_STRICT` | `false` | Fail spawns when firewall rule apply fails |
| `FIREWALL_USE_NSENTER` | `false` | Execute firewall commands in the host netns via `nsenter` |
| `PCAP_ENABLED` | `true` | Enable packet-capture sidecars for new instances |
| `PCAP_MODE` | `all` | Packet-capture policy for future spawns |
| `PCAP_SELECTED_CHALLENGES` | - | Comma-separated challenge IDs for selected-mode capture |
| `PCAP_MAX_SIZE_MB` | `25` | Rotate packet-capture files when they reach this size |
| `PCAP_RETENTION_HOURS` | `24` | Delete capture directories older than this many hours |
| `PCAP_SNAP_LEN` | `1024` | Capture snap length in bytes |
| `PCAP_BPF_FILTER` | `not (host 127.0.0.11 and port 53)` | Default filter for new captures |

## ⚠️ Capacity Planning & Server Requirements

### Infrastructure Overhead

Whaley's production infrastructure adds minimal overhead:

| Component | RAM | CPU | Disk | Notes |
|-----------|-----|-----|------|-------|
| **Whaley App** | ~100 MB | 0.1-0.5 cores | — | FastAPI + uvicorn |
| **Redis** | ~50 MB | 0.05 cores | ~10 MB | Distributed locking |
| **SQLite DB** | ~5 MB | minimal | 1-50 MB | Grows with events |
| **Network Isolation** | ~1 MB/network | minimal | — | Per-instance bridge + iptables |
| **PCAP Parser** | 50-200 MB peak | burst only | — | On-demand when admin views flows |
| **Total Fixed Overhead** | **~200 MB** | **~0.5 cores** | **~60 MB** | Before any instances |

### Per-Instance Resource Cost

Each spawned instance consumes the following resources:

| Component | RAM | CPU | Disk/hr | Notes |
|-----------|-----|-----|---------|-------|
| Challenge containers (avg) | 256 MB | 0.5 cores | — | Capped by `CONTAINER_MAX_MEMORY` |
| tcpdump sidecar | ~5 MB | 0.02 cores | 5–25 MB | When `PCAP_ENABLED=true` |
| Isolated network | ~1 MB | negligible | — | iptables rules + bridge veth |
| Forensics log (on terminate) | — | — | ~30 KB | Compressed gzip |
| Docker metadata | ~2 MB | — | ~0.5 KB | Labels, state, overlay layers |
| **Total per instance** | **~264 MB** | **~0.52 cores** | **5–25 MB** | With PCAP + forensics |

### PCAP Disk Usage by Challenge Type

The biggest storage variable is packet capture. Rates assume `PCAP_SNAP_LEN=1024` and BPF filter active:

| Challenge Type | Typical PCAP Rate | Worst Case | Notes |
|----------------|-------------------|------------|-------|
| Static web (Nginx) | 2-5 MB/hr | 15 MB/hr | Mostly GET requests |
| Dynamic web (Flask/Node) | 5-15 MB/hr | 30 MB/hr | API calls, form submits |
| PWN (socat + binary) | 1-3 MB/hr | 10 MB/hr | Short exploit payloads |
| Crypto/Rev service | 1-5 MB/hr | 15 MB/hr | Depends on protocol |
| Multi-service (DB+app+bot) | 10-25 MB/hr | 50 MB/hr | Internal chatter between services |
| A/D game service | 20-80 MB/hr | 150 MB/hr | Continuous attack/defense traffic |

> 💡 **Tip**: Use `PCAP_MODE=selected` with `PCAP_SELECTED_CHALLENGES` to capture only the challenges you care about and significantly reduce disk usage.

### Server Specifications

#### Minimum (Small Events: ≤50 teams)

| Resource | Minimum | Notes |
|----------|---------|-------|
| CPU | 4 cores | 2 for Docker, 2 for app/Redis |
| RAM | 16 GB | ~200 MB overhead + ~264 MB per instance |
| Storage | 60 GB SSD | Docker images + PCAPs (~10 GB for 8h event) |
| Network | 100 Mbps | Adequate for small events |
| OS | Ubuntu 22.04+ / Debian 12+ | Docker 24.0+ recommended |

#### Recommended (Medium Events: 50-200 teams)

| Resource | Recommended | Notes |
|----------|-------------|-------|
| CPU | 8 cores | Parallel spawns, network creation |
| RAM | 32 GB | ~264 MB per instance + overhead |
| Storage | 150 GB NVMe SSD | Docker images + PCAPs (~20-40 GB) |
| Network | 1 Gbps | High bandwidth for many connections |
| OS | Ubuntu 22.04 LTS | Stable, well-tested |

#### High-Load (Large Events: 200+ teams)

| Resource | High-Load | Notes |
|----------|-----------|-------|
| CPU | 16+ cores | Parallel network/container ops |
| RAM | 64 GB+ | Enables 200+ concurrent instances |
| Storage | 300 GB NVMe | PCAPs dominate storage (~30-60 GB) |
| Network | 1 Gbps+ | Consider load balancing |
| Database | PostgreSQL | Replace SQLite for multi-worker |

### Capacity Estimation

#### Formula
```
Base Overhead = 200 MB (Whaley + Redis + SQLite)
Per-Instance = Challenge RAM + Sidecar (5 MB) + Network (~1 MB) + Metadata (~2 MB)

Hard Cap = Teams × MAX_INSTANCES_PER_TEAM  (default: 2)
Peak Instances = Hard Cap × Concurrency Factor (0.5-0.8)

Total RAM = Base Overhead + (Peak Instances × Avg Instance RAM)
Total Disk = Docker Images + (PCAP Instances × PCAP Rate/hr × Event Hours)
Ports Required = Peak Instances × Ports per Challenge
Networks Required = Peak Instances × (1 isolation network + compose-defined networks)
```

#### Example: National CTF (150 teams, Team Mode)

```
Event Profile:
- Teams: 150 (using TEAM_MODE=enabled)
- MAX_INSTANCES_PER_TEAM: 2
- Instanced challenges: 8 challenges
- Avg ports per challenge: 2
- Avg RAM per instance: 264 MB (256 MB challenge + 5 MB sidecar + 3 MB overhead)
- PCAP_MODE: all
- Event duration: 10 hours

Peak Load Calculation:
- Hard cap: 150 × 2 = 300 instances max
- Peak instances: 300 × 0.7 = ~210 instances
- RAM: 200 MB + (210 × 264 MB) = ~56 GB
- Ports: 210 × 2 = 420 ports
- Networks: 210 isolated networks, plus any compose-defined challenge networks
- PCAP storage: 210 × 10 MB/hr × 10 hr = ~21 GB
- Forensics logs: ~1500 terminates × 30 KB = ~45 MB
- SQLite size: ~10 MB (event logs + port mappings)

Realistic Deployment:
- Server: 16 cores, 64 GB RAM, 200 GB NVMe
- Workers: 1 (SQLite) or 4 (PostgreSQL + Redis)
- PORT_RANGE: 10000-40000 (30,000 ports)
- INSTANCE_TIMEOUT: 1800 (30 min)
- MAX_INSTANCES_PER_TEAM: 2
- PCAP_RETENTION_HOURS: 24
```

### Configuration by Event Size

#### Small Event (≤50 teams) - Single Worker

```env
# Infrastructure
DATABASE_URL=sqlite+aiosqlite:///./data/whaley.db
# REDIS_URL not needed for single worker

# Limits
PORT_RANGE_START=20000
PORT_RANGE_END=30000
MAX_INSTANCES_PER_USER=2
MAX_INSTANCES_PER_TEAM=2
INSTANCE_TIMEOUT=3600  # 1 hour

# Network Isolation
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true

# Packet Capture
PCAP_ENABLED=true
PCAP_MODE=all
PCAP_MAX_SIZE_MB=25
PCAP_RETENTION_HOURS=24
PCAP_SNAP_LEN=1024
```

#### Medium Event (50-150 teams) - With Redis

```env
# Infrastructure
DATABASE_URL=sqlite+aiosqlite:///./data/whaley.db
REDIS_URL=redis://redis:6379/0

# Limits
PORT_RANGE_START=10000
PORT_RANGE_END=40000
MAX_INSTANCES_PER_USER=2
MAX_INSTANCES_PER_TEAM=2
INSTANCE_TIMEOUT=1800  # 30 minutes

# Network Isolation
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true

# Packet Capture
PCAP_ENABLED=true
PCAP_MODE=all
PCAP_MAX_SIZE_MB=25
PCAP_RETENTION_HOURS=24
PCAP_SNAP_LEN=1024
```

#### Large Event (150-300 teams) - Multi-Worker

```env
# Infrastructure (PostgreSQL for multi-worker)
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/whaley
REDIS_URL=redis://redis:6379/0

# Limits
PORT_RANGE_START=10000
PORT_RANGE_END=50000
MAX_INSTANCES_PER_USER=2
MAX_INSTANCES_PER_TEAM=2
INSTANCE_TIMEOUT=1200  # 20 minutes

# Network Isolation
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true

# Packet Capture — use selected mode to save disk
PCAP_ENABLED=true
PCAP_MODE=selected
PCAP_SELECTED_CHALLENGES=web-challenge-1,web-challenge-2,pwn-challenge-1
PCAP_MAX_SIZE_MB=25
PCAP_RETENTION_HOURS=12
PCAP_SNAP_LEN=512
```

## 🧪 Stress Testing

Whaley ships with a reusable stress harness at [scripts/stress_test.py](/mnt/c/1Jonathan/CTFS/research-dir/whaley/scripts/stress_test.py). The script is aimed at rehearsal runs against a live deployment and focuses on the places where event infra usually starts to creak:

- challenge discovery from `/challenges`
- synthetic team-owned spawns through `/admin/api/instances/spawn`
- mixed HTTP and raw TCP traffic against the spawned instances
- periodic snapshots from `/admin/api/instances` and `/admin/api/pcap/status`
- optional cleanup through `/admin/api/instances/{id}`

### Why Use the Admin API in `AUTH_MODE=none`

In `AUTH_MODE=none`, Whaley identifies normal users by client IP. If you drive the public `/instances/spawn` API from one machine, Whaley will mostly see one user instead of hundreds of simulated teams. The stress harness avoids that blind spot by using the admin spawn API and assigning synthetic `team_id` / `team_name` values to each spawned owner.

### Prerequisites

Install the Python dependencies first:

```bash
pip install -r requirements.txt
```

You also need:

- a deployment where the supplied `ADMIN_KEY` works
- active challenges visible from `/challenges`
- enough free ports, RAM, and disk for the rehearsal you are about to run

### Quick Smoke Test

This is the safest first pass. It creates a small batch of instances, drives light traffic for two minutes, and tears everything down automatically.

```bash
WHALEY_BASE_URL=http://your-server:8000 \
WHALEY_ADMIN_KEY=your-admin-key \
python3 scripts/stress_test.py \
  --team-count 10 \
  --instances-per-team 2 \
  --traffic-seconds 120 \
  --traffic-workers 16 \
  --team-prefix smoke \
  --cleanup
```

### Large Rehearsal

This shape is closer to a serious pre-event soak:

```bash
WHALEY_BASE_URL=http://your-server:8000 \
WHALEY_ADMIN_KEY=your-admin-key \
python3 scripts/stress_test.py \
  --team-count 160 \
  --instances-per-team 2 \
  --traffic-seconds 900 \
  --traffic-workers 64 \
  --spawn-concurrency 8 \
  --admin-qps 2.0 \
  --team-prefix fullrun \
  --state-file /tmp/whaley-stress.json
```

What those knobs do:

- `--team-count`: number of synthetic teams to simulate
- `--instances-per-team`: unique challenges per team; this must not exceed the number of discovered active challenges
- `--traffic-seconds`: soak duration after the spawn phase
- `--traffic-workers`: concurrent traffic loops
- `--spawn-concurrency`: max in-flight admin spawn/stop requests from the harness
- `--admin-qps`: pacing for admin mutations so you do not immediately collide with admin rate limiting
- `--team-prefix`: gives each run a unique synthetic owner namespace
- `--state-file`: saves created instance IDs so cleanup can be retried later

### Cleanup Later

If you omit `--cleanup`, the script saves created instances into the state file. You can stop them later with:

```bash
WHALEY_BASE_URL=http://your-server:8000 \
WHALEY_ADMIN_KEY=your-admin-key \
python3 scripts/stress_test.py \
  --cleanup-from-state /tmp/whaley-stress.json
```

### Suggested Progression

Run the rehearsal in stages instead of jumping straight to the ugliest case:

1. `10 teams x 2 instances` with `--cleanup`
2. `40 teams x 2 instances`, longer traffic, still auto-cleanup
3. `160 teams x 2 instances` without cleanup so you can inspect metrics and PCAP growth
4. cleanup from the saved state file

This keeps basic spawn bugs separate from long-run pressure like disk growth, sidecar instability, or Docker network churn.

### What to Watch During the Run

- `/admin/api/instances`: total instance count and `starting/running/error` mix
- `/admin/api/pcap/status`: capture instance count, file count, and `total_size_mb`
- `/metrics`: Prometheus counters and gauges for instance lifecycle, ports, and storage
- Docker host memory, CPU, and disk usage
- sidecar restarts or `OOMKilled` flags on `whaley-pcap` containers

### Tuning Notes

- Keep `--spawn-concurrency` close to Whaley's internal spawn semaphore. The default is 10 concurrent spawns, so values like `8` or `10` are a good fit.
- If admin requests start returning `429`, lower `--admin-qps` or temporarily raise `ADMIN_RATE_LIMIT`.
- The script discovers challenges dynamically from `/challenges`, so inactive challenges are skipped automatically.
- Traffic generation is intentionally generic. For deeper realism, extend the harness with challenge-specific HTTP paths or protocol payloads.


### Resource Limits per Challenge

Each challenge's `docker-compose.yaml` should define limits:

```yaml
services:
  web:
    build: .
    ports:
      - "${PORT_80:-8080}:80"
    deploy:
      resources:
        limits:
          cpus: '0.5'      # Max 0.5 CPU cores
          memory: 256M     # Max 256MB RAM
        reservations:
          memory: 64M      # Guaranteed minimum
    # Prevent fork bombs
    ulimits:
      nproc: 100           # Max 100 processes
      nofile:
        soft: 1024
        hard: 2048
```

Whaley enforces global caps (`CONTAINER_MAX_MEMORY`, `CONTAINER_MAX_CPU`, and `CONTAINER_PIDS_LIMIT`) on every service before startup. If a challenge requests a larger limit, the global cap wins.

### Recommended Limits by Challenge Type

| Challenge Type | CPU | Memory | Processes | Notes |
|----------------|-----|--------|-----------|-------|
| Static Web | 0.25 | 128 MB | 50 | Nginx, static files |
| Dynamic Web (Flask/Node) | 0.5 | 256 MB | 100 | Most common |
| PWN (binary) | 0.5 | 128 MB | 50 | socat + binary |
| Crypto/Rev | 0.25 | 64 MB | 25 | Minimal services |
| Complex (multi-service) | 1.0 | 512 MB | 150 | DB + app + bot |

### Network Isolation Impact

With `NETWORK_ISOLATION_ENABLED=true`, each instance gets its own Docker bridge network:

| Instances | Networks Created | Overhead |
|-----------|------------------|----------|
| 50 | 50 networks | ~50 MB, 50 iptables rules |
| 200 | 200 networks | ~200 MB, 200 iptables rules |
| 500 | 500 networks | ~500 MB, may need kernel tuning |

**Kernel Parameters for Large Events (500+ networks):**
```bash
# /etc/sysctl.conf
net.bridge.bridge-nf-call-iptables = 1
net.netfilter.nf_conntrack_max = 1048576
```

### Monitoring & Pre-Event Checklist

#### Before Event
```bash
# Test concurrent spawns
for i in {1..20}; do
  curl -X POST http://localhost:8000/instances/spawn \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"challenge_id":"test-challenge"}' &
done
wait

# Check infrastructure health
curl http://localhost:8000/health

# Monitor resources
docker stats
htop
```

#### During Event
- Monitor `/health` endpoint for instance count
- Watch disk space: `df -h`
- Check PCAP storage: `du -sh logs/pcaps/`
- Check Docker networks: `docker network ls | wc -l`
- Check database size: `ls -lh data/whaley.db`
- Redis stats: `redis-cli info memory`

#### Key Metrics to Watch

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| RAM Usage | >70% | >90% | Reduce INSTANCE_TIMEOUT |
| CPU Usage | >80% sustained | >95% | Limit concurrent spawns |
| Disk Usage | >70% | >85% | Trigger PCAP cleanup, reduce retention |
| PCAP Storage | >50 GB | >100 GB | Switch to `PCAP_MODE=selected` or reduce `PCAP_SNAP_LEN` |
| Active Networks | >400 | >500 | May need kernel tuning |
| SQLite Size | >100 MB | >500 MB | Consider PostgreSQL |
| Redis Memory | >100 MB | >500 MB | Check for lock leaks |

---

## 🔍 Instance Forensics (Docker Log Capture)

Instance Forensics allows capturing container logs for debugging and analysis. This feature has two modes:

### Feature Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Auto Capture** | Automatically dump logs when instances terminate | Post-mortem analysis, debugging user issues |
| **Live Capture** | On-demand log capture from running containers | Real-time debugging without stopping instances |

### Configuration

```env
# Enable auto capture (default: false, can toggle via admin panel)
FORENSICS_AUTO_CAPTURE=false

# Size limits (prevent disk exhaustion)
FORENSICS_MAX_SIZE_MB=5         # Max log size per instance
FORENSICS_TAIL_LINES=1000       # Max lines per container

# Storage
FORENSICS_RETENTION_HOURS=24    # Auto-delete logs older than this (24 = 1 day)
FORENSICS_COMPRESSION=true      # Compress with gzip (~90% savings)
FORENSICS_LOG_DIR=/app/logs/forensics
```

### Server Resource Impact

> ⚠️ **Important**: Auto Capture impacts server resources. Size your server accordingly.

#### Resource Analysis

| Resource | Impact | Mitigation |
|----------|--------|------------|
| **Disk Space** | +10-20 GB buffer needed | Compression + retention |
| **Disk I/O** | Burst writes on terminate | NVMe SSD recommended for large events |
| **CPU** | ~2-5% per concurrent dump | Semaphore limits (max 5) |
| **Memory** | ~600 KB per dump | Negligible |

#### Disk Usage Estimation

```
Per Instance Log:
- Uncompressed: 100-500 KB (tail 1000 lines × 3 containers)
- Compressed: 10-50 KB (gzip ~90% compression)

Event Calculation (150 teams, 8h event):
- Instances terminated: ~3600 (multiple spawns per challenge)
- Logs per instance: 30 KB compressed
- Total: 3600 × 30 KB = ~108 MB

With 24-hour retention (default):
- Max storage: ~108 MB (very manageable)

Note: Forensic logs are negligible compared to PCAP storage.
PCAP captures dominate disk usage at 5-25 MB/hr per instance.
```

#### Burst Write Scenario (Event End)

When an event ends, many instances terminate simultaneously:

```
150 teams × 3 active instances = 450 terminates
Log dump per instance: 300 KB, 3 seconds
Concurrent dumps: 5 (semaphore limited)

Total write: 450 × 300 KB = 135 MB
Duration: (450 / 5) × 3 = 4.5 minutes
Write speed required: ~0.5 MB/s (any SSD handles this easily)
```

### Recommended Configuration by Event Size

#### Small Event (≤50 teams)
```env
FORENSICS_AUTO_CAPTURE=true     # Safe to enable
FORENSICS_TAIL_LINES=500
FORENSICS_MAX_SIZE_MB=2
FORENSICS_RETENTION_HOURS=24    # 1 day
```

**Additional server requirement:** +1 GB disk (negligible)

#### Medium Event (50-150 teams)
```env
FORENSICS_AUTO_CAPTURE=true     # Enable with monitoring
FORENSICS_TAIL_LINES=1000
FORENSICS_MAX_SIZE_MB=5
FORENSICS_RETENTION_HOURS=24    # 1 day
FORENSICS_COMPRESSION=true
```

**Additional server requirement:** +1 GB disk (negligible vs PCAP storage)

#### Large Event (150-300 teams)
```env
FORENSICS_AUTO_CAPTURE=false    # Consider Live Capture only
FORENSICS_TAIL_LINES=500
FORENSICS_MAX_SIZE_MB=3
FORENSICS_RETENTION_HOURS=12    # 12 hours
FORENSICS_COMPRESSION=true
```

**Considerations:**
- Use Live Capture for on-demand debugging instead
- Forensic logs are tiny — PCAP storage is the real disk concern
- **Additional requirement:** +1 GB disk

### Using Instance Forensics

#### Via Admin Dashboard

1. Navigate to **Whaley Logs** → **Instance Forensics** tab
2. Toggle **Auto Capture** on/off as needed
3. For Live Capture:
   - Select a running instance from dropdown
   - Click **Capture Now**
4. View logs by clicking the 👁️ icon
5. Download or copy logs as needed

#### Via API

```bash
# Get forensics stats
curl -X GET "http://localhost:8000/admin/api/forensics/stats" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Toggle auto capture
curl -X POST "http://localhost:8000/admin/api/forensics/toggle?enabled=true" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# List all logs
curl -X GET "http://localhost:8000/admin/api/forensics/logs" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Live capture from running instance
curl -X POST "http://localhost:8000/admin/api/forensics/live-capture/{instance_id}" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Get log content
curl -X GET "http://localhost:8000/admin/api/forensics/logs/{log_id}" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Cleanup old logs manually
curl -X POST "http://localhost:8000/admin/api/forensics/cleanup" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"
```

Use `X-Admin-Key: <ADMIN_KEY>` instead when `AUTH_MODE=none`.

---

### Best Practices

1. **Start with Auto Capture OFF** - Enable only when needed for debugging
2. **Use Live Capture for debugging** - Less resource intensive than Auto Capture
3. **Monitor disk usage** - Set up alerts for disk >80%
4. **Shorter retention for large events** - 3 days instead of 7
5. **Enable compression** - Reduces disk usage by ~90%
6. **Review logs regularly** - Delete unnecessary logs to save space

### 📝 Enhanced Logging with Middleware (For Challenge Authors)

Instance Forensics captures **stdout/stderr** from Docker containers. For more detailed logging (request bodies, headers, etc.), challenge authors can add middleware to their applications.

> 💡 **Important**: The examples below are **templates/suggestions only**. Challenge authors are **free to use any logging method** they prefer. Whaley does not enforce or depend on any specific logging library or format. As long as your application logs to **stdout/stderr**, Instance Forensics will capture it automatically.

#### Freedom of Implementation

You are **not tied to Whaley** for logging implementation:

- ✅ Use **any logging library** (Python logging, Winston, Loguru, Bunyan, etc.)
- ✅ Use **any log format** (JSON, plain text, custom format)
- ✅ Use **any middleware** (custom, third-party, or none at all)
- ✅ Use **your own logging infrastructure** (external services like Sentry, Datadog, etc.)
- ✅ **No dependency on Whaley** - your challenge code remains portable

**The only requirement**: If you want Whaley's Instance Forensics to capture your logs, print them to **stdout** or **stderr**. That's it!

#### Why Use App-Level Middleware?

| Feature | Docker Logs Only | With Middleware |
|---------|------------------|------------------|
| Container stdout/stderr | ✅ Yes | ✅ Yes |
| HTTP request details | ❌ No | ✅ Yes |
| Request body/payload | ❌ No | ✅ Yes |
| Request headers | ❌ No | ✅ Yes |
| Response status | ❌ No | ✅ Yes |
| Structured JSON logs | ❌ No | ✅ Yes |
| Selective filtering | ❌ No | ✅ Yes (hide passwords) |

#### Quick Implementation Examples

**The following are just examples** - feel free to adapt or use your own solution!

**For Flask Applications:**

```python
# Add to your challenge's app.py
import logging
import json
from datetime import datetime
from io import BytesIO

logger = logging.getLogger("challenge")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

class DetailedRequestLogger:
    """WSGI middleware for detailed request/response logging."""
    
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        import time
        start_time = time.time()
        
        # Log request
        log_data = {
            "event": "request",
            "timestamp": datetime.utcnow().isoformat(),
            "method": environ.get("REQUEST_METHOD"),
            "path": environ.get("PATH_INFO"),
            "query": environ.get("QUERY_STRING"),
            "remote_addr": environ.get("REMOTE_ADDR"),
            "user_agent": environ.get("HTTP_USER_AGENT"),
        }
        
        # Capture body for POST/PUT/PATCH
        if environ.get("REQUEST_METHOD") in ["POST", "PUT", "PATCH"]:
            try:
                content_length = int(environ.get("CONTENT_LENGTH", 0))
                if 0 < content_length <= 1024 * 1024:  # Max 1MB
                    body = environ["wsgi.input"].read(content_length)
                    log_data["body"] = body.decode("utf-8", errors='ignore')[:1000]
                    # Re-wrap for app consumption
                    environ["wsgi.input"] = BytesIO(body)
            except Exception as e:
                log_data["body_error"] = str(e)
        
        logger.info(json.dumps(log_data))
        
        # Execute app
        def custom_start_response(status, headers, exc_info=None):
            response_log = {
                "event": "response",
                "timestamp": datetime.utcnow().isoformat(),
                "path": environ.get("PATH_INFO"),
                "status": status.split()[0],
                "duration_ms": int((time.time() - start_time) * 1000)
            }
            logger.info(json.dumps(response_log))
            return start_response(status, headers, exc_info)
        
        return self.app(environ, custom_start_response)

# Usage in Flask:
from flask import Flask

app = Flask(__name__)

# Add middleware
app.wsgi_app = DetailedRequestLogger(app.wsgi_app)

# Your routes...
@app.route('/api/data', methods=['POST'])
def api_endpoint():
    # Your code
    pass
```

**For FastAPI Applications:**

```python
# Add to your challenge's main.py
import logging
import json
from datetime import datetime
from fastapi import Request
import time

logger = logging.getLogger("challenge")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log request
    body = await request.body()
    log_data = {
        "event": "request",
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": request.url.path,
        "query": str(request.query_params),
        "client": request.client.host,
        "body": body.decode('utf-8')[:1000] if body else None
    }
    logger.info(json.dumps(log_data))
    
    # Execute request
    response = await call_next(request)
    
    # Log response
    response_log = {
        "event": "response",
        "timestamp": datetime.utcnow().isoformat(),
        "path": request.url.path,
        "status": response.status_code,
        "duration_ms": int((time.time() - start_time) * 1000)
    }
    logger.info(json.dumps(response_log))
    
    return response
```

#### What Gets Captured

With this middleware, Instance Forensics will capture:

```json
{"event":"request","timestamp":"2026-01-08T10:30:15.123Z","method":"POST","path":"/api/login","query":"debug=1","remote_addr":"192.168.1.100","user_agent":"Mozilla/5.0...","body":"{\"username\":\"admin\",\"password\":\"test123\"}"}
{"event":"response","timestamp":"2026-01-08T10:30:15.456Z","path":"/api/login","status":"200","duration_ms":333}
```

#### Security Considerations

⚠️ **Important**: Be careful with sensitive data!

```python
# BAD - Logs passwords
log_data["body"] = body.decode('utf-8')

# GOOD - Filter sensitive fields
import json
try:
    body_json = json.loads(body)
    # Remove sensitive fields
    body_json.pop('password', None)
    body_json.pop('token', None)
    log_data["body"] = json.dumps(body_json)
except:
    log_data["body"] = "<binary or invalid json>"
```

#### Testing

After adding middleware:

1. Start your challenge locally: `docker compose up`
2. Make a request: `curl -X POST http://localhost:5000/api/test -d '{"data":"test"}'`
3. Check logs: `docker compose logs web`
4. You should see JSON-formatted request/response logs

#### Integration with Whaley

Once deployed to Whaley:

1. Middleware logs go to **stdout** → captured by Docker
2. Instance Forensics **Auto Capture** saves logs on terminate
3. Or use **Live Capture** to dump logs anytime
4. View in Admin Dashboard → Whaley Logs → Instance Forensics

**Result**: You get detailed HTTP logs alongside container logs, perfect for:
- Debugging user issues
- Detecting exploit attempts
- Understanding user behavior
- Post-CTF analysis

#### Example Use Cases

| Scenario | Without Middleware | With Middleware |
|----------|-------------------|------------------|
| User reports "login doesn't work" | Only see container startup logs | See exact request body sent by user |
| Debugging failed exploit | No visibility into HTTP traffic | See all request/response pairs |
| Finding intended solution | Guess from app code | Replay successful request from logs |
| Detecting abuse | Only see error messages | See full attack payloads |

#### Alternative Logging Approaches

**You're not limited to the examples above!** Here are other common approaches:

##### Using Existing Logging Libraries

**Python:**
```python
# Using loguru (more advanced features)
from loguru import logger
import sys

logger.remove()  # Remove default handler
logger.add(sys.stdout, format="{time} | {level} | {message}", level="INFO")

@app.before_request
def log_request():
    logger.info(f"Request: {request.method} {request.path} - Body: {request.get_data()}")
```

**Node.js:**
```javascript
// Using winston or morgan
const morgan = require('morgan');
app.use(morgan('combined'));  // Logs to stdout by default
```

**Go:**
```go
// Using standard log package
import "log"
import "os"

log.SetOutput(os.Stdout)
log.Printf("Request: %s %s from %s\n", method, path, remoteAddr)
```

##### External Logging Services

If you prefer external logging (Sentry, Datadog, Logtail, etc.), you can use them **in addition to** or **instead of** stdout logging:

```python
# Dual logging: both to stdout and external service
import logging
import sentry_sdk

# Whaley will capture stdout
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

# Your external service (optional)
sentry_sdk.init("your-dsn")
```

**Benefits:**
- ✅ Real-time monitoring during CTF
- ✅ Advanced analytics and alerting
- ✅ Longer retention (beyond Whaley's limits)
- ✅ Keep logs even after challenge deletion

**Note**: External services are **your responsibility** - Whaley doesn't manage them.

##### Reverse Proxy Approach

Some authors prefer logging at the reverse proxy layer:

```yaml
# docker-compose.yaml in your challenge
services:
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    ports:
      - "80:80"
    depends_on:
      - app
  
  app:
    build: .
    expose:
      - "5000"
```

```nginx
# nginx.conf
http {
    log_format detailed '$remote_addr - $time_local "$request" '
                       '$status $body_bytes_sent "$http_user_agent"';
    
    access_log /dev/stdout detailed;  # Docker will capture this
    
    server {
        listen 80;
        location / {
            proxy_pass http://app:5000;
        }
    }
}
```

##### No Logging at All

**It's perfectly fine to not add detailed logging!** 

- Default Docker logs (stdout/stderr from your app) are often sufficient
- Instance Forensics will still capture basic container output
- You can always add logging later if needed

**Remember**: Whaley doesn't care **how** you log or **what** you log. It simply captures whatever your containers print. The choice is yours!

---

## 📡 Native Packet Capture

Whaley can attach a lightweight `tcpdump` sidecar to each new instance spawn and keep the resulting `.pcap` files under `/app/logs/pcaps/{instance_id}` for incident response, traffic review, and anti-cheat analysis.

### Configuration

```env
PCAP_ENABLED=true
PCAP_MODE=all
PCAP_SELECTED_CHALLENGES=
PCAP_MAX_SIZE_MB=25
PCAP_RETENTION_HOURS=24
PCAP_SNAP_LEN=1024
PCAP_BPF_FILTER=not (host 127.0.0.11 and port 53)
```

- `PCAP_MODE`: `all`, `selected`, or `none` for future spawns
- `PCAP_SELECTED_CHALLENGES`: challenge IDs used when the mode is `selected`
- `PCAP_MAX_SIZE_MB`: rotated file size cap used by `tcpdump -C`
- `PCAP_RETENTION_HOURS`: how long captures are kept before cleanup removes them
- `PCAP_SNAP_LEN`: snap length used for each packet
- `PCAP_BPF_FILTER`: default filter trims Docker embedded DNS noise

### How it works

- New instances get a `whaley-pcap` sidecar that shares the instance network namespace
- Captures are rotated into per-instance directories, compressed after rotation, and kept after the instance stops
- The admin dashboard lists captures from lightweight metadata and parses flows on demand with `scapy`
- Packet-capture sidecars are excluded from the regular per-instance logs/metrics views so the challenge containers stay front and center

### Using the dashboard

1. Open **Whaley Logs** -> **Packet Capture**
2. Choose the policy for future spawns: **Capture All**, **Capture Selected**, or **Capture Disabled**
3. If using selected mode, tick the challenge IDs that should get packet capture
4. Select an instance that has capture files
5. Filter by protocol, search payloads, or restrict to flows tagged with `contains_flag`
6. Click a flow to inspect packet previews and the follow-stream payload view
7. Use **Download Raw Capture** to export the underlying `.pcap` files
8. Use **Cleanup Old** to remove capture directories older than `PCAP_RETENTION_HOURS`

### API examples

```bash
# Capture status and storage usage
curl -X GET "http://localhost:8000/admin/api/pcap/status" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# List flows for one instance
curl -X GET "http://localhost:8000/admin/api/pcap/instances/{instance_id}/flows?protocol=HTTP&flagged_only=true" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Search payloads for a token or flag fragment
curl -X GET "http://localhost:8000/admin/api/pcap/instances/{instance_id}/search?q=FLAG%7B" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Download the raw PCAP bundle
curl -L -X GET "http://localhost:8000/admin/api/pcap/instances/{instance_id}/download" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN" \
     -o instance_capture.zip
```

### Prometheus metrics

When `METRICS_SECRET` is configured, `/metrics` also exposes:

- `whaley_pcap_instances_total`
- `whaley_pcap_total_size_bytes`
- `whaley_pcap_enabled`

### Operational notes

- Packet capture is preserved after instance teardown so it can be reviewed later
- Cleanup runs in the background alongside forensics retention cleanup
- Disk is the main resource to watch; use retention and BPF filters to keep it under control

---

## 🔍 Resource Monitoring

Whaley includes native resource monitoring to track host pressure and, when requested, sampled Docker CPU/memory usage for the currently visible page of instances. This keeps the admin dashboard responsive during large events while still giving you drill-down detail when you need it.

### Features

| Feature | Description | Use Case |
|---------|-------------|----------|
| **System Overview** | Host load average, memory, disk, and tracked container count | Monitor overall server health |
| **Instance Inventory** | Paginated list of active instances without Docker stats by default | Keep the dashboard responsive at high instance counts |
| **Per-Page Metrics Sampling** | CPU & RAM usage aggregated only for the visible page | Identify resource-hungry challenges without sweeping all containers |
| **Per-Container Metrics** | Detailed metrics for each container | Pinpoint specific container issues |
| **High Usage Filter** | Show only instances with CPU >50% or RAM >80% | Quick identification of problems |
| **Firewall Status** | Show connlimit/hashlimit policy, tracked rule counts, and stale rules | Confirm host DoS protection is active |
| **Real-Time Updates** | Refresh host snapshot on-demand | Live monitoring during events |

### Accessing Monitoring

#### Via Admin Dashboard

1. Navigate to **Admin Dashboard** → **Monitoring** tab
2. View **System Overview** card showing:
   - Total/running containers
   - Host load averages and CPU core count
   - Host memory usage and disk usage
3. Review **Firewall Rate Limits** to confirm the backend, policy, and stale-rule count
4. Scroll to **Instance Inventory** section
5. (Optional) Enable "Show high usage only" filter
6. Click **Sample Page Metrics** when you need Docker CPU/RAM details for the current page
7. Expand instance cards to see per-container details or use the **Firewall** button for per-instance rule state

#### Via API

```bash
# Get system metrics
curl -X GET "http://localhost:8000/admin/api/monitoring/system" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Response:
{
  "total_containers": 15,
  "running_containers": 15,
  "host_cpu_cores": 8,
  "host_memory_total_mb": 16384.0,
  "host_memory_used_mb": 8192.0,
  "host_memory_percent": 50.0,
  "loadavg_1": 1.12,
  "loadavg_5": 0.94,
  "loadavg_15": 0.81,
  "disk_total_gb": 200.0,
  "disk_used_gb": 84.5,
  "disk_percent": 42.3,
  "timestamp": "2026-01-09T10:30:00Z"
}

# Get the paginated instance inventory (lightweight by default)
curl -X GET "http://localhost:8000/admin/api/monitoring/instances?limit=20&offset=0" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Response:
{
  "instances": [
    {
      "instance_id": "web-1-abc123",
      "challenge_id": "web-challenge",
      "challenge_name": "Example Web Challenge",
      "owner_id": "user123",
      "owner_name": "alice",
      "container_count": 3,
      "metrics_available": false,
      "metrics_sampled": false,
      "total_cpu_percent": null,
      "total_memory_mb": null,
      "containers": [],
      "message": null
    }
  ],
  "total_instances": 1,
  "limit": 20,
  "offset": 0,
  "include_metrics": false
}

# Sample Docker metrics for just the current page
curl -X GET "http://localhost:8000/admin/api/monitoring/instances?limit=20&offset=0&include_metrics=true" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# Response:
{
  "instances": [
    {
      "instance_id": "web-1-abc123",
      "challenge_id": "web-challenge",
      "challenge_name": "Example Web Challenge",
      "owner_id": "user123",
      "owner_name": "alice",
      "container_count": 3,
      "metrics_available": true,
      "metrics_sampled": true,
      "total_cpu_percent": 25.5,
      "total_memory_mb": 512.3,
      "containers": [
        {
          "container_id": "abc123456789",
          "container_name": "web-1-abc123-web-1",
          "cpu_percent": 15.2,
          "memory_usage_mb": 256.1,
          "memory_limit_mb": 512.0,
          "memory_percent": 50.0,
          "pids": 12
        }
      ],
      "timestamp": "2026-01-09T10:30:00Z"
    }
  ],
  "total_instances": 1
}
```

For a single instance, use the admin instance metrics endpoint. This is what the dashboard's **Metrics** button calls:

```bash
curl -X GET "http://localhost:8000/admin/api/instances/{instance_id}/metrics" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"
```

### Firewall Rate-Limit Status

Whaley can apply host-level `connlimit` and `hashlimit` rules for each published challenge port. Rules are installed when an instance finishes spawning, removed when it stops or expires, and cleaned up periodically on startup/maintenance in case the process previously crashed.

Important notes:

- Whaley targets Docker published ports via `DOCKER-USER`, not plain `INPUT`
- Matching uses the original destination port through conntrack
- If Whaley runs inside a container, use `FIREWALL_USE_NSENTER=true` or equivalent host firewall access
- `FIREWALL_STRICT=false` lets an instance run even if firewall rule apply fails, but the admin dashboard will show degraded status

```bash
# Global firewall status
curl -X GET "http://localhost:8000/admin/api/firewall/status" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"

# One instance's tracked rules
curl -X GET "http://localhost:8000/admin/api/firewall/instances/web-1-abc123" \
     -H "Authorization: Bearer $CTFD_ADMIN_TOKEN"
```

For Prometheus scraping, set `METRICS_SECRET` and scrape `/metrics`:

```yaml
scrape_configs:
  - job_name: whaley
    metrics_path: /metrics
    static_configs:
      - targets: ["your-instancer:8000"]
    authorization:
      type: Bearer
      credentials: "your-metrics-secret"
```

### Understanding Metrics

#### CPU Percentage

- **Per-Container**: Percentage of one CPU core (can exceed 100% on multi-core systems)
- **Per-Instance**: Sum of all containers in the instance
- **Total System**: Sum of all containers (useful to see total load)

**Example**:
- Container A: 50% (using half of one core)
- Container B: 120% (using 1.2 cores on multi-core system)
- Instance Total: 170%
- If host has 4 cores → actual load is 170% / 4 = 42.5% of total capacity

#### Memory Metrics

- **Usage MB**: Actual RAM used by container
- **Limit MB**: Memory limit set in docker-compose (if any)
- **Percent**: `(Usage / Limit) * 100`
- **Host Memory**: Total physical RAM and current usage

### Usage Thresholds

Whaley uses color-coded badges for quick identification:

| Metric | Green (OK) | Yellow (Warning) | Red (Danger) |
|--------|------------|------------------|--------------|
| CPU | < 50% | 50-80% | > 80% |
| Memory | < 60% | 60-80% | > 80% |

### Common Scenarios

#### High CPU Usage

**Symptoms**: Container CPU > 80%

**Possible Causes**:
- Legitimate heavy workload (brute force, crypto mining, CPU-bound exploit)
- Infinite loop in challenge code
- Fork bomb or excessive process spawning
- DDoS attack on web service

**Actions**:
1. Check Instance Forensics logs for suspicious activity
2. Use Live Capture to dump current logs
3. Consider stopping the instance if abuse detected
4. Review challenge code for bugs

#### High Memory Usage

**Symptoms**: Container memory > 80% of limit

**Possible Causes**:
- Memory leak in challenge code
- Large file uploads
- Memory exhaustion exploit
- Insufficient memory limits

**Actions**:
1. Check if memory limit is set in docker-compose.yaml
2. Review challenge resource requirements
3. Check logs for error messages
4. Consider increasing memory limit or fixing leak

#### System Overload

**Symptoms**: Total CPU or host memory > 90%

**Actions**:
1. Enable "Show high usage only" filter
2. Identify top resource consumers
3. Consider implementing auto-cleanup for old instances
4. Add more server resources or scale horizontally

### Best Practices

1. **Regular Monitoring**: Check metrics during CTF events (every 15-30 minutes)
2. **Set Memory Limits**: Always define `mem_limit` in challenge docker-compose
3. **Baseline Testing**: Test challenges locally to understand expected resource usage
4. **Alert Thresholds**: Set up external monitoring (Prometheus, Grafana) for production
5. **Documentation**: Document expected resource usage in challenge.yaml

### Performance Overhead

The monitoring system has minimal impact:

- **API Calls**: Uses `docker stats --no-stream` (single snapshot, not continuous)
- **CPU Impact**: < 1% (only during refresh)
- **Memory Impact**: Negligible (~5MB for monitoring process)
- **Frequency**: On-demand only (admin must click refresh)

### Limitations

- **Update Frequency**: Metrics are not real-time, refresh manually via button
- **Historical Data**: No historical tracking (use external monitoring for trends)
- **Alerting**: No built-in alerts (admin must actively check)
- **Network I/O**: Available in per-instance metrics detail and API
- **Disk I/O**: Available in per-instance metrics detail and API

### External Monitoring Integration

For production deployments, consider integrating external monitoring:

**Whaley `/metrics`**:

Use the built-in protected Prometheus endpoint for Whaley-level metrics: instance counts/status, owner/team/challenge breakdowns, per-instance age/expiry, port pool usage, dynamic flags, suspicious submissions, forensics storage, packet-capture storage, and event counters.

**cAdvisor + Grafana**:
```yaml
# docker-compose.yaml
services:
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    ports:
      - "8080:8080"
```

**Node Exporter** (for host metrics):
```yaml
  node-exporter:
    image: prom/node-exporter:latest
    ports:
      - "9100:9100"
```

Then configure Prometheus to scrape Whaley, cAdvisor, and Node Exporter for long-term storage and alerting.

---

## 🔒 Security

### Considerations

1. **Firewall** - Only open necessary ports (API port + instance range)
2. **Admin RBAC** - In CTFd mode, use CTFd admin users for `/admin`; in no-auth mode protect `ADMIN_KEY` like a password
3. **Resource Limits** - Set proper `mem_limit` and `cpus` in challenges; Whaley also enforces global caps
4. **Network Isolation** - Keep per-instance network isolation enabled for production
5. **Compose Hardening** - Challenge compose files cannot use privileged mode, host/container namespaces, custom `network_mode`, added capabilities/devices, unsafe security options, Docker socket mounts, external networks/volumes, unsafe build or env-file paths, or bind mounts outside the challenge directory. `security_opt: ["no-new-privileges:true"]` is allowed.
6. **Trusted Proxies** - Configure `TRUSTED_PROXIES` when using no-auth mode behind a reverse proxy so client identity cannot be spoofed with forwarded headers
7. **Timeouts** - Set reasonable instance timeouts
8. **Rate Limiting** - Admin APIs have built-in per-IP limits; add edge rate limiting for public endpoints in high-traffic events
9. **Metrics Secret** - Set a strong `METRICS_SECRET` before exposing `/metrics`; leave it empty to disable the endpoint
10. **Lifecycle Cleanup** - Keep Docker labels intact; they allow Whaley to identify and clean stale per-instance resources safely

### Persistent Port Mapping

The instancer implements **persistent port mapping**:

- When a user spawns a challenge for the first time, they receive randomly allocated ports
- The port mapping is saved in the database (`user_port_mappings`)
- When the instance expires and the user spawns the same challenge again, they receive the **same ports**

**How it works:**
```
User A spawns "web-challenge" → Gets port 32456
Instance expires
User A spawns "web-challenge" again → Gets port 32456 (same!)
```

### Dynamic Flags

When `DYNAMIC_FLAGS_ENABLED=true`, each user receives a **unique flag** per challenge:

1. **Flag Generation** - When user spawns an instance, a unique flag is generated (e.g., `FLAG{ab0bd3c5...}`)
2. **Flag Injection** - The flag is automatically injected into challenge files:
   - `flag`, `flag.txt`, `flag-*`, `flag_*`
   - `Dockerfile`, `docker-compose.yaml`
   - Source files in `src/`, `app/`, `challenge/` directories
3. **CTFd Registration** - The flag is registered with CTFd for that specific user
4. **Submission Monitoring** - When "Check Now" is clicked, recent CTFd submissions are scanned
5. **Cheating Detection** - If User B submits User A's flag, it's logged as suspicious

Flag mappings, challenge mappings, submission scan checkpoints, and suspicious submissions are stored in the database. Whaley enforces uniqueness for owner/challenge flag mappings, flag content, and suspicious submission keys to prevent duplicate flag rows or repeated suspicious entries after restarts, retries, or full scans. Legacy `logs/flag_mappings.json` data is imported once if present.

Flag injection only replaces same-line patterns like `FLAG{placeholder}`. Unclosed placeholders such as `FLAG{` do not match across newlines, which prevents accidental corruption of later source code braces or shell `${variables}`.

**Setup:**

1. Set environment variables:
   ```env
   DYNAMIC_FLAGS_ENABLED=true
   CTFD_API_KEY=ctfd_your_admin_token_here
   FLAG_PREFIX=FLAG  # or STORM, CTF, etc.
   ```

2. In your challenge files, use placeholder flags:
   ```
   FLAG{placeholder}
   ```
   The instancer will replace these with unique flags per user.

3. Map local challenges to CTFd using **Sync Wizard** (recommended):
   - Go to **Admin Panel → Dynamic Flags → Challenge ID Mapping**
   - Click **"Sync Wizard"** button
   - The wizard will fetch all challenges from CTFd automatically
   - Challenges with matching names are highlighted with **⚡ Match Found**
   - Select a local challenge from dropdown and click **"Map"**
   - Already mapped challenges show **✓ Mapped** and can be unmapped

   **Manual Mapping** (alternative):
   - Expand "Manual Mapping (advanced)" section
   - Select your local challenge and enter the corresponding CTFd challenge ID
   - Click "Add"

4. Monitor for cheating:
   - Go to **Admin Panel → Dynamic Flags**
   - Click "Check Now" to scan recent submissions
   - Suspicious submissions will appear in the table

**How it detects cheating:**
```
User A spawns instance → Gets FLAG{abc123...}
User B spawns instance → Gets FLAG{def456...}
User B submits FLAG{abc123...} (User A's flag)
→ Detected as suspicious! Logged with submitter info, flag owner, timestamp, IP
```

### CTFd Sync Wizard

The **Sync Wizard** simplifies mapping local challenges to CTFd challenges:

**Features:**
- 🔄 **Auto-Fetch** - Fetches all challenges from CTFd API with one click
- 🔍 **Search & Filter** - Filter by name or category
- ⚡ **Smart Matching** - Auto-detects name matches between local and CTFd challenges
- ✅ **Visual Status** - See which challenges are already mapped
- 🎯 **One-Click Mapping** - Map with pre-selected suggestions

**How name matching works:**
- **Exact match (100%)** - Local challenge name equals CTFd name (case-insensitive)
- **Partial match (50%)** - One name contains the other (e.g., "Web 1" matches "Basic Web 1")
- Suggested matches are highlighted in yellow with "⚡ Match Found" badge

**Using the Sync Wizard:**
1. Navigate to **Admin Panel → Dynamic Flags → Challenge ID Mapping**
2. Click the **"🔄 Sync Wizard"** button
3. The modal shows all CTFd challenges with their categories and point values
4. Challenges with name matches show a suggested local challenge in the dropdown
5. Select/adjust the local challenge and click **"Map"**
6. Mapped challenges show a green **"✓ Mapped"** badge with an "Unmap" button

**API Endpoint:**
```
GET /admin/api/ctfd/challenges?search=web&category=Web
```

Returns CTFd challenges with mapping suggestions for each.

### Team Mode

Whaley supports **CTFd Team Mode** where instances and dynamic flags are shared per-team instead of per-user. This is essential for team-based CTF competitions.

#### Configuration

```env
# Team mode setting (in .env or docker-compose.yaml)
TEAM_MODE=auto      # Auto-detect from CTFd (recommended)
TEAM_MODE=enabled   # Force team mode regardless of CTFd config
TEAM_MODE=disabled  # Force user mode regardless of CTFd config

# Team-specific instance limit
MAX_INSTANCES_PER_TEAM=5
```

#### Behavior Differences

| Feature | User Mode | Team Mode |
|---------|-----------|-----------|
| **Instance Ownership** | Per-user | Per-team (shared) |
| **Instance Limit** | `MAX_INSTANCES_PER_USER` per user | `MAX_INSTANCES_PER_TEAM` per team |
| **Dynamic Flags** | Unique per user | Shared per team |
| **Who Can Stop/Extend** | Only the user who spawned | Any team member |
| **Instance Visibility** | Only user's instances | All team instances |
| **Cheating Detection** | User A submits User B's flag | Team A submits Team B's flag |
| **Port Allocation** | Per-user persistence | Per-team persistence |

#### Auto-Detection

With `TEAM_MODE=auto` (default), Whaley automatically detects CTFd's competition mode:

1. At startup, queries CTFd API: `GET /api/v1/configs/user_mode`
2. If response is `"teams"` → Team mode enabled
3. If response is `"users"` → User mode enabled
4. Result is cached until auth/CTFd settings are changed or the service restarts

#### How Team Mode Works

**Spawning:**
```
User A (Team Alpha) spawns "web-challenge"
→ Instance created for Team Alpha
→ Dynamic flag generated for Team Alpha: FLAG{team_alpha_unique_123}

User B (Team Alpha, same team) sees the instance in their dashboard
User B can extend or stop the instance

User C (Team Beta, different team) spawns "web-challenge"
→ Separate instance created for Team Beta
→ Different flag: FLAG{team_beta_unique_456}
```

**Cheating Detection in Team Mode:**
```
Team Alpha's flag: FLAG{alpha123}
Team Beta's flag: FLAG{beta456}

User from Team Beta submits FLAG{alpha123}
→ Detected as suspicious! 
→ Logged: "Team Beta member submitted Team Alpha's flag"
```

#### API Changes in Team Mode

**GET /me** response includes team info:
```json
{
    "user": {
        "user_id": "123",
        "username": "john",
        "team_id": "456",
        "team_name": "Alpha Team"
    },
    "instances": 2,
    "max_instances": 5,
    "team_mode": true
}
```

**GET /config** endpoint:
```json
{
    "team_mode": true,
    "max_instances_per_user": 3,
    "max_instances_per_team": 5,
    "instance_timeout": 1800,
    "auth_mode": "ctfd"
}
```

**GET /instances** returns team's instances in team mode (not just user's).

#### Frontend Display

When team mode is enabled, the user dashboard shows:
- Team name alongside username
- "Team Instances" label instead of "Instances"
- All team members' spawned instances
- Who spawned each instance (for transparency)

### Challenge Manager Security

- Uploads reject traversal paths, absolute paths, Windows absolute paths, and symlinks
- File operations stay inside `./challenges/` and cannot target the challenge root as a file
- Binary files are non-editable; text writes are capped at 2 MB
- Runtime spawns reject symlinked challenge trees before Docker build/start
- Deleting a challenge with active instances is blocked
- Admin auth is required for all management operations

---

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - feel free to use this for your CTF events!
