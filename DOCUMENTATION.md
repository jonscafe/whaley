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
- [Instance Forensics](#-instance-forensics-docker-log-capture)
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

# Your VPS public IP or domain (use "auto" for auto-detection)
PUBLIC_HOST=auto

# Port range for instances
PORT_RANGE_START=20000
PORT_RANGE_END=50000

# Admin dashboard access key (generate with: openssl rand -hex 32)
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
| `ADMIN_KEY` | - | Secret key for admin dashboard access |
| `CTFD_API_KEY` | - | CTFd admin API key (for dynamic flags) |
| `DYNAMIC_FLAGS_ENABLED` | `false` | Enable per-user dynamic flags |
| `FLAG_PREFIX` | `FLAG` | Prefix for generated flags (e.g., `FLAG{...}`) |
| `LOG_FILE` | `logs/events.jsonl` | Path to event log file |
| `DEBUG` | `false` | Enable debug mode |

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

### Tips for Challenge Authors

- **No `container_name`** - Don't use container_name to allow multiple instances
- **Use PORT env vars** - Always use `${PORT_<internal>}` for exposed ports
- **Set resource limits** - Add `mem_limit` and `cpus` to prevent abuse
- **Multi-port challenges** - List all ports in challenge.yaml that users need to access
- **Internal services** - Services like bots that don't need external access don't need port mappings

---

## 🔌 API Reference

### Health & Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI (user interface) |
| `/api` | GET | API info |
| `/health` | GET | Detailed health status |

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

### Admin (requires ADMIN_KEY)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin` | GET | Admin dashboard UI |
| `/admin/api/stats` | GET | Get system statistics |
| `/admin/api/instances` | GET | List all active instances |
| `/admin/api/logs` | GET | Get event logs (with filtering) |

### Challenge Management (requires ADMIN_KEY)

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

### Dynamic Flags / Anti-Cheat (requires ADMIN_KEY)

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

#### CTFd Sync Wizard API

```bash
# Fetch all CTFd challenges with mapping info
curl -H "X-Admin-Key: YOUR_KEY" \
  "http://localhost:8000/admin/api/ctfd/challenges"

# Filter by search term
curl -H "X-Admin-Key: YOUR_KEY" \
  "http://localhost:8000/admin/api/ctfd/challenges?search=web"

# Filter by category
curl -H "X-Admin-Key: YOUR_KEY" \
  "http://localhost:8000/admin/api/ctfd/challenges?category=Web"
```

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

Users authenticate with their CTFd access token. The token is validated via CTFd's API (`/api/v1/users/me`).

**Via API:**
```bash
curl -H "Authorization: Token YOUR_CTFD_TOKEN" \
  http://your-instancer:8000/challenges
```

**Via Web UI:**
1. Open `http://your-instancer:8000/` in browser
2. Enter your CTFd access token when prompted
3. Token is saved in browser localStorage for convenience

To get a CTFd token, users go to CTFd → Settings → Access Tokens.

### No Auth Mode

Users are identified by IP address. No authentication required:

```bash
curl http://your-instancer:8000/challenges
```

---

## 📊 Admin Dashboard

Access the admin dashboard at `http://your-instancer:8000/admin`

The admin dashboard has 3 pages:

### 1. Dashboard
- 📈 **Statistics** - Total spawns, active instances, unique users
- 🖥️ **Active Instances** - View all running instances with force-stop capability

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

**Authentication:** Enter the `ADMIN_KEY` configured in your `.env` file.

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

- All file operations are protected with path traversal checks
- Binary files are marked as non-editable
- Challenge directories are isolated within `./challenges/`

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

Prevents race conditions when running multiple Gunicorn workers.

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
- ✅ No subprocess spawning (more secure)
- ✅ Better error handling with typed exceptions
- ✅ Native container/network lifecycle management
- ✅ Proper resource cleanup

#### 4. Network Isolation

Each instance runs in its own isolated Docker bridge network.

**Features:**
- 🔒 Instances cannot communicate with each other
- 🛡️ Prevents lateral movement attacks between challenges
- 🧪 Automatic network cleanup on instance termination

**Configuration:**
```env
# Enable network isolation (recommended)
NETWORK_ISOLATION_ENABLED=true

# Disable inter-container communication
NETWORK_ICC_DISABLED=true

# Network name prefix
NETWORK_PREFIX=whaley
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

## ⚠️ Capacity Planning & Server Requirements

### Infrastructure Overhead

Whaley's production infrastructure adds minimal overhead:

| Component | RAM | CPU | Disk | Notes |
|-----------|-----|-----|------|-------|
| **Whaley App** | ~100 MB | 0.1-0.5 cores | - | FastAPI + uvicorn |
| **Redis** | ~50 MB | 0.05 cores | ~10 MB | Distributed locking |
| **SQLite DB** | ~5 MB | minimal | 1-50 MB | Grows with events |
| **Network Isolation** | ~1 MB/network | minimal | - | Per-instance overhead |
| **Total Overhead** | ~200 MB | ~0.5 cores | ~100 MB | Before any instances |

### Server Specifications

#### Minimum (Small Events: ≤50 teams)

| Resource | Minimum | Notes |
|----------|---------|-------|
| CPU | 4 cores | 2 for Docker, 2 for app/Redis |
| RAM | 8 GB | ~150 MB overhead + ~100 MB per instance |
| Storage | 40 GB SSD | Docker images + SQLite + logs |
| Network | 100 Mbps | Adequate for small events |
| OS | Ubuntu 22.04+ / Debian 12+ | Docker 24.0+ recommended |

#### Recommended (Medium Events: 50-200 teams)

| Resource | Recommended | Notes |
|----------|-------------|-------|
| CPU | 8-16 cores | Parallel spawns, network creation |
| RAM | 32-64 GB | ~256 MB per instance + overhead |
| Storage | 100-200 GB NVMe SSD | Fast I/O for Docker + SQLite |
| Network | 1 Gbps | High bandwidth for many connections |
| OS | Ubuntu 22.04 LTS | Stable, well-tested |

#### High-Load (Large Events: 200+ teams)

| Resource | High-Load | Notes |
|----------|-----------|-------|
| CPU | 32+ cores | Parallel network/container ops |
| RAM | 128 GB+ | Enables 400+ concurrent instances |
| Storage | 500 GB NVMe | Fast storage critical |
| Network | 10 Gbps | Consider load balancing |
| Database | PostgreSQL | Replace SQLite for multi-worker |

### Capacity Estimation

#### Formula
```
Base Overhead = 200 MB (Whaley + Redis + SQLite)
Per-Instance = Container RAM + Network (~1 MB) + Metadata (~1 KB)

Total RAM = Base Overhead + (Concurrent Instances × Avg Instance RAM)
Ports Required = Concurrent Instances × Ports per Challenge
Networks Required = Concurrent Instances (1 network per instance)

Concurrency Factor:
- Jeopardy CTF: 0.3-0.5 (not all teams active simultaneously)
- Attack-Defense: 0.8-1.0 (all teams need instances)
```

#### Example: National CTF (150 teams, Team Mode)

```
Event Profile:
- Teams: 150 (using TEAM_MODE=enabled)
- Instanced challenges: 8 challenges
- Avg ports per challenge: 2
- Avg RAM per instance: 256 MB

Peak Load Calculation:
- Concurrent instances: 150 × 8 × 0.4 = 480 instances
- RAM: 200 MB + (480 × 256 MB) = ~123 GB
- Ports: 480 × 2 = 960 ports
- Networks: 480 isolated networks
- SQLite size: ~10 MB (event logs + port mappings)

Realistic Deployment:
- Server: 16 cores, 64 GB RAM, 200 GB NVMe
- Workers: 1 (SQLite) or 4 (PostgreSQL + Redis)
- PORT_RANGE: 10000-40000 (30,000 ports)
- INSTANCE_TIMEOUT: 1800 (30 min)
- MAX_INSTANCES_PER_TEAM: 5
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
MAX_INSTANCES_PER_USER=5
MAX_INSTANCES_PER_TEAM=8
INSTANCE_TIMEOUT=3600  # 1 hour

# Network Isolation
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true
```

#### Medium Event (50-150 teams) - With Redis

```env
# Infrastructure
DATABASE_URL=sqlite+aiosqlite:///./data/whaley.db
REDIS_URL=redis://redis:6379/0

# Limits
PORT_RANGE_START=10000
PORT_RANGE_END=40000
MAX_INSTANCES_PER_USER=3
MAX_INSTANCES_PER_TEAM=5
INSTANCE_TIMEOUT=1800  # 30 minutes

# Network Isolation
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true
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
MAX_INSTANCES_PER_TEAM=4
INSTANCE_TIMEOUT=1200  # 20 minutes

# Network Isolation
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true
```

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
- Check Docker networks: `docker network ls | wc -l`
- Check database size: `ls -lh data/whaley.db`
- Redis stats: `redis-cli info memory`

#### Key Metrics to Watch

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| RAM Usage | >70% | >90% | Reduce INSTANCE_TIMEOUT |
| CPU Usage | >80% sustained | >95% | Limit concurrent spawns |
| Disk Usage | >80% | >90% | Cleanup Docker images |
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
FORENSICS_RETENTION_HOURS=168   # Auto-delete logs older than this (168 = 7 days)
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

With 7-day retention:
- Daily events: ~108 MB/day
- Max storage: ~756 MB (very manageable)
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
FORENSICS_RETENTION_HOURS=72    # 3 days
```

**Additional server requirement:** +10 GB disk

#### Medium Event (50-150 teams)
```env
FORENSICS_AUTO_CAPTURE=true     # Enable with monitoring
FORENSICS_TAIL_LINES=1000
FORENSICS_MAX_SIZE_MB=5
FORENSICS_RETENTION_HOURS=168   # 7 days
FORENSICS_COMPRESSION=true
```

**Additional server requirement:** +20 GB SSD (NVMe recommended)

#### Large Event (150-300 teams)
```env
FORENSICS_AUTO_CAPTURE=false    # Consider Live Capture only
FORENSICS_TAIL_LINES=500
FORENSICS_MAX_SIZE_MB=3
FORENSICS_RETENTION_HOURS=72    # 3 days
FORENSICS_COMPRESSION=true
```

**Considerations:**
- Use Live Capture for on-demand debugging instead
- Or separate log storage disk/mount
- **Additional requirement:** +30 GB NVMe SSD

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
     -H "X-Admin-Key: your-key"

# Toggle auto capture
curl -X POST "http://localhost:8000/admin/api/forensics/toggle?enabled=true" \
     -H "X-Admin-Key: your-key"

# List all logs
curl -X GET "http://localhost:8000/admin/api/forensics/logs" \
     -H "X-Admin-Key: your-key"

# Live capture from running instance
curl -X POST "http://localhost:8000/admin/api/forensics/live-capture/{instance_id}" \
     -H "X-Admin-Key: your-key"

# Get log content
curl -X GET "http://localhost:8000/admin/api/forensics/logs/{log_id}" \
     -H "X-Admin-Key: your-key"

# Cleanup old logs manually
curl -X POST "http://localhost:8000/admin/api/forensics/cleanup" \
     -H "X-Admin-Key: your-key"
```

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

## � Resource Monitoring

Whaley includes native resource monitoring to track CPU and memory usage of containers and the host system. This helps identify resource-intensive instances and prevent server overload.

### Features

| Feature | Description | Use Case |
|---------|-------------|----------|
| **System Overview** | Host CPU cores, total memory, container count | Monitor overall server health |
| **Per-Instance Metrics** | CPU & RAM usage aggregated by instance | Identify resource-hungry challenges |
| **Per-Container Metrics** | Detailed metrics for each container | Pinpoint specific container issues |
| **High Usage Filter** | Show only instances with CPU >50% or RAM >80% | Quick identification of problems |
| **Real-Time Updates** | Refresh metrics on-demand | Live monitoring during events |

### Accessing Monitoring

#### Via Admin Dashboard

1. Navigate to **Admin Dashboard** → **Monitoring** tab
2. View **System Overview** card showing:
   - Total/running containers
   - Total CPU usage (% and cores available)
   - Total memory usage (MB and host %)
3. Scroll to **Instance Resource Usage** section
4. (Optional) Enable "Show high usage only" filter
5. Click "Refresh" button to update metrics
6. Expand instance cards to see per-container details

#### Via API

```bash
# Get system metrics
curl -X GET "http://localhost:8000/admin/api/monitoring/system" \
     -H "X-Admin-Key: your-key"

# Response:
{
  "total_containers": 15,
  "running_containers": 15,
  "total_cpu_percent": 45.3,
  "total_memory_mb": 1024.5,
  "host_cpu_cores": 8,
  "host_memory_total_mb": 16384.0,
  "host_memory_used_mb": 8192.0,
  "host_memory_percent": 50.0,
  "timestamp": "2026-01-09T10:30:00Z"
}

# Get per-instance metrics
curl -X GET "http://localhost:8000/admin/api/monitoring/instances" \
     -H "X-Admin-Key: your-key"

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
- **Network I/O**: Shown but not prominently featured in UI
- **Disk I/O**: Available via API but not in main UI view

### External Monitoring Integration

For production deployments, consider integrating external monitoring:

**Prometheus + Grafana**:
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

Then configure Prometheus to scrape these endpoints for long-term storage and alerting.

---

## �🔒 Security

### Considerations

1. **Firewall** - Only open necessary ports (API port + instance range)
2. **Resource Limits** - Set proper mem_limit and cpus in challenges
3. **Network Isolation** - Consider separate networks per instance
4. **Timeouts** - Set reasonable instance timeouts
5. **Rate Limiting** - Add rate limiting for production (e.g., slowapi)

### Persistent Port Mapping

The instancer implements **persistent port mapping**:

- When a user spawns a challenge for the first time, they receive randomly allocated ports
- The port mapping is saved to `logs/user_ports.json`
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
4. Result is cached for the application lifetime

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

- All file operations are protected with path traversal checks
- Binary files are marked as non-editable
- Challenge directories are isolated within `./challenges/`
- Admin key required for all management operations

---

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - feel free to use this for your CTF events!
