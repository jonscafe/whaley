<h1 align="center">🐳 Whaley</h1>
<h3 align="center">Dedicated Docker Instancer for CTF Competitions</h3>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 📋 Overview

**Whaley** is a production-ready Docker instance manager designed specifically for Capture The Flag (CTF) competitions. Deploy it on a dedicated server to provide each participant with their own isolated challenge environment—complete with automatic port allocation, resource limits, and seamless CTFd integration.

### Why Whaley?

| Problem | Whaley's Solution |
|---------|-------------------|
| Shared challenge instances cause interference | 🔒 **Isolated containers** per user/team |
| Manual port management is error-prone | 🎯 **Automatic port allocation** with collision prevention |
| No visibility into player resource usage | 📊 **Real-time monitoring** dashboard |
| Difficult to detect flag sharing | 🔍 **Suspicious submission detection** |
| Need packet-level evidence during incidents | 📡 **Native packet capture** with flow search and raw PCAP download |
| Complex setup for dynamic flags | 💉 **Simple CTFd integration** with auto flag injection |
| Need external observability | 📈 **Prometheus `/metrics`** endpoint protected by a secret |

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🚀 Core Functionality
- **Dynamic Instance Spawning** — Isolated Docker containers per user/team
- **Automatic Port Allocation** — Smart port management (default range 30000-40000, configurable)
- **Multi-Port Challenges** — Support for complex multi-service challenges
- **Auto-Cleanup** — Instances automatically terminated after timeout
- **Startup Orphan Cleanup** — Removes stale compose projects, networks, volumes, and per-spawn images
- **Docker Compose Support** — Standard `.yaml` and `.yml` formats
- **Enforced Resource Limits** — Global memory, CPU & PID caps enforced on all containers
- **Per-Challenge Resource Overrides** — Fine-tune limits per challenge from admin panel

### 🔐 Authentication & Security
- **CTFd Integration** — Validate users and admin RBAC via CTFd access tokens
- **No-Auth Mode** — IP-based identification for open events
- **Network Isolation** — Each instance in its own Docker network
- **Host Firewall Rate Limits** — Per-instance connlimit/hashlimit rules on published challenge ports
- **Distributed Locking** — Redis-based locks for multi-worker safety
- **Fork Bomb Protection** — PID limits per container

</td>
<td width="50%" valign="top">

### 🚩 Dynamic Flags
- **Unique Flags** — Each user/team gets unique flag per challenge
- **Auto Flag Injection** — Inject flags into challenge files at build time
- **CTFd Registration** — Automatically register flags with CTFd
- **Submission Monitoring** — Detect and log flag sharing attempts
- **Team Mode Support** — Shared flags per team when enabled
- **Database Persistence** — Flag mappings and suspicious submissions survive restarts with duplicate protection

### 📊 Monitoring & Admin
- **Host-First Monitoring** — Fast host load/memory/disk snapshot that stays responsive at high instance counts
- **On-Demand Page Sampling** — Sample Docker CPU/RAM only for the visible monitoring page when you need detail
- **Prometheus Metrics** — Protected `/metrics` endpoint for external scraping
- **Instance Forensics** — Capture logs on termination or on-demand
- **Native Packet Capture** — Per-instance tcpdump sidecar, searchable flows, payload viewer, lazy PCAP indexing, and raw PCAP download
- **Admin Dashboard** — Left-sidebar (GZCTF/CTFd-style) web UI for monitoring and management, including manual spawn/destroy, firewall status, and paginated high-volume views
- **Per-Instance Logs & Metrics** — Inspect Docker logs and CPU/RAM/network/block I/O from the dashboard
- **Challenge Manager** — Upload & edit challenges without SSH; one-click **Copy Link** to a challenge's public page
- **Public Challenge Links** — Standalone `/instance/{id}` page per challenge, shareable on its own; admins can **Sync Public Link to CTFd** so it appears in the CTFd challenge's connection info
- **Challenge Toggle** — Activate/deactivate challenges from admin panel
- **Admin Settings UI** — Configure all Whaley settings via the web UI (no env/compose edits needed)
- **Event Logging** — Comprehensive audit trail with Docker errors

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- Docker Engine 24.0+ with Docker Compose v2
- 4+ CPU cores, 8GB+ RAM (see [capacity planning](#-capacity-planning))
- Linux server (Ubuntu 22.04+ or Debian 12+ recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/jonscafe/whaley.git
cd whaley

# Configure environment
cp .env.example .env
nano .env  # Edit with your settings

# Start Whaley
docker compose up -d
```

### Access Points

| Interface | URL | Description |
|-----------|-----|-------------|
| **User Dashboard** | `http://your-server:8000/` | Challenge spawning interface |
| **Admin Panel** | `http://your-server:8000/admin` | Monitoring & management |
| **Public Challenge Link** | `http://your-server:8000/instance/{challenge_id}` | Standalone page for a single challenge |
| **API Docs** | `http://your-server:8000/docs` | Swagger API documentation |
| **Prometheus Metrics** | `http://your-server:8000/metrics` | Protected metrics export when `METRICS_SECRET` is set |

---

## ⚙️ Configuration

### Essential Settings

```env
# Authentication
AUTH_MODE=ctfd                    # "ctfd" or "none"
CTFD_URL=https://your-ctfd.com    # Your CTFd instance URL
CTFD_API_KEY=ctfd_xxx...          # CTFd admin API key for dynamic flags/sync

# Network
PUBLIC_HOST=auto                  # VPS IP ("auto" for detection)
PORT_RANGE_START=30000            # Default range; widen if you expect >10k concurrent ports
PORT_RANGE_END=40000

# Admin
ADMIN_KEY=your-secure-key         # Local admin key when AUTH_MODE=none
METRICS_SECRET=change-me          # Enables protected /metrics endpoint

# Dynamic Flags
DYNAMIC_FLAGS_ENABLED=true
FLAG_PREFIX=FLAG                  # e.g., FLAG{...}

# Packet Capture
PCAP_ENABLED=true
PCAP_MODE=all                    # "all", "selected", or "none"
PCAP_MAX_SIZE_MB=25
PCAP_RETENTION_HOURS=24
PCAP_SNAP_LEN=1024
PCAP_BPF_FILTER=not (host 127.0.0.11 and port 53)

# Team Mode
TEAM_MODE=auto                    # "auto", "enabled", or "disabled"
```

### Production Settings (Optional)

```env
# PostgreSQL for high availability
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/whaley

# Redis for distributed locking (required for multiple workers)
REDIS_URL=redis://redis:6379/0

# Network Isolation (recommended)
NETWORK_ISOLATION_ENABLED=true
NETWORK_ICC_DISABLED=true
NETWORK_SUBNET_BASE=10.240.0.0/16
NETWORK_SUBNET_PREFIX=28

# Host Firewall Rate Limits (recommended for public events)
FIREWALL_RATE_LIMIT_ENABLED=true
FIREWALL_CHAIN=DOCKER-USER
FIREWALL_CONN_LIMIT_PER_IP=60
FIREWALL_RATE_PER_MINUTE=120
FIREWALL_RATE_BURST=240
FIREWALL_REJECT_MODE=reject

TRUSTED_PROXIES=127.0.0.1,::1     # Only these proxies may set client IP headers

# Resource Limits (enforced on all containers)
CONTAINER_MAX_MEMORY=384m         # Max memory per container
CONTAINER_MAX_CPU=0.5             # Max CPU cores per container
CONTAINER_PIDS_LIMIT=256          # Max PIDs per container (fork bomb protection)
```

> 💡 **Tip**: Most settings (including Authentication & CTFd integration) can be configured instantly via the **Admin Panel → ⚙️ Settings** tab.

> 🔐 **Admin access**: In `AUTH_MODE=ctfd`, Whaley validates the submitted CTFd access token with CTFd's `/api/v1/users/me`, then fetches `/api/v1/users/{id}` and only enables `/admin` when that detailed user record has `type: "admin"`. In `AUTH_MODE=none`, admin APIs use the local `ADMIN_KEY` fallback.

> 🌐 **Subnet pool**: Whaley uses `NETWORK_SUBNET_BASE` / `NETWORK_SUBNET_PREFIX` for both its per-instance isolation network and compose-defined challenge networks. This keeps multi-network challenges from exhausting Docker's default address pools during large events.

> 🛡️ **Host rate limits**: Enable `FIREWALL_RATE_LIMIT_ENABLED=true` to install per-instance `connlimit` + `hashlimit` rules on Docker published ports via `DOCKER-USER`. If Whaley itself runs inside a container, set `FIREWALL_USE_NSENTER=true` or provide equivalent host firewall access.

> 📈 **Prometheus metrics**: Set `METRICS_SECRET` to enable `/metrics`. Scrape with either `Authorization: Bearer <secret>` or `X-Metrics-Secret: <secret>`.

> 📖 **Full configuration guide**: See [DOCUMENTATION.md](DOCUMENTATION.md#configuration)

---

## 📁 Challenge Structure

Create challenges in the `challenges/` directory:

```
challenges/
└── my-web-challenge/
    ├── challenge.yaml        # Challenge metadata
    ├── docker-compose.yaml   # Container definition
    ├── Dockerfile
    ├── flag.txt              # Flag file (auto-injected)
    └── src/
        └── app.py
```

### challenge.yaml

```yaml
id: my-web-challenge
name: "SQL Injection Lab"
category: web
description: "Can you bypass the login?"
ports:
  - 80
timeout: 3600  # 1 hour
```

### docker-compose.yaml

```yaml
services:
  web:
    build: .
    ports:
      - "${PORT_80}:80"
    environment:
      - FLAG=${FLAG}
    mem_limit: 256m
    cpus: 0.5
```

> ⚠️ **Resource enforcement**: Even if a challenge sets `mem_limit: 2g`, Whaley will cap it to the global `CONTAINER_MAX_MEMORY` (default `384m`). You can set per-challenge overrides via the admin panel.

> 🛡️ **Compose hardening**: Whaley prepares every spawn from a per-instance copy, attaches the instance network automatically, and rejects dangerous compose options such as `privileged`, `network_mode`, host/container namespace sharing, added capabilities/devices, unsafe security options, Docker socket mounts, external networks/volumes, unsafe build/env file paths, symlinks, and bind mounts that escape the challenge directory. The hardening-safe `security_opt: ["no-new-privileges:true"]` option is allowed.

> 📖 **More examples**: See [DOCUMENTATION.md](DOCUMENTATION.md#challenge-structure)

---

## 👥 Team Mode

Whaley supports CTFd Team Mode where instances and flags are shared per-team:

| Feature | User Mode | Team Mode |
|---------|:---------:|:---------:|
| Instance Ownership | Per user | Per team |
| Dynamic Flags | Unique per user | Shared per team |
| Instance Control | Only spawner | Any team member |
| Suspicious Detection | User vs User | Team vs Team |

Enable with `TEAM_MODE=auto` to automatically detect from CTFd settings.

---

## 📊 Capacity Planning

### Estimation Formula

```
Hard Cap = Teams × MAX_INSTANCES_PER_TEAM  (default: 2)
Peak Instances = Hard Cap × Concurrency Factor (0.5 – 0.8)
RAM Required = 200 MB (infra) + Peak Instances × 264 MB
Storage Required = Docker Images + (PCAP Instances × PCAP Rate × Hours)
Ports Required = Peak Instances × Ports per Challenge
```

### Per-Instance Resource Cost

| Component | RAM | CPU | Disk/hr | Notes |
|-----------|-----|-----|---------|-------|
| Challenge containers (avg) | 256 MB | 0.5 cores | — | Capped by `CONTAINER_MAX_MEMORY` |
| tcpdump sidecar | ~5 MB | 0.02 cores | 5–25 MB | When `PCAP_ENABLED=true` |
| Isolated network | ~1 MB | negligible | — | Per-instance bridge + iptables |
| Forensics log (on terminate) | — | — | ~30 KB | Compressed gzip |
| **Total per instance** | **~264 MB** | **~0.52 cores** | **5–25 MB** | Sidecar included |

### Server Recommendations

| Event Size | CPU | RAM | Storage | Example |
|------------|:---:|:---:|:-------:|--------|
| **Small** (≤50 teams) | 4 cores | 16 GB | 60 GB SSD | Local CTFs |
| **Medium** (50-150 teams) | 8 cores | 32 GB | 150 GB NVMe | University CTFs |
| **Large** (150-300 teams) | 16 cores | 64 GB | 300 GB NVMe | National CTFs |

### Example Calculations

> **Scenario A — University CTF**: 100 teams, 8 challenges, 10-hour event
>
> - Hard cap: 100 × 2 = 200 instances max
> - Peak instances: 200 × 0.7 = **140 instances**
> - RAM: 200 MB + 140 × 264 MB = **~37 GB**
> - PCAP storage: 140 × 10 MB/hr × 10 hr = **~14 GB**
> - Ports: 140 × 1.5 avg = **210 ports**

> **Scenario B — National CTF**: 200 teams, 10 challenges, 12-hour event
>
> - Hard cap: 200 × 2 = 400 instances max
> - Peak instances: 400 × 0.7 = **280 instances**
> - RAM: 200 MB + 280 × 264 MB = **~74 GB**
> - PCAP storage: 280 × 10 MB/hr × 12 hr = **~34 GB**
> - Ports: 280 × 1.5 avg = **420 ports**

---

## 🧪 Stress Testing

Whaley includes a reusable stress harness at [scripts/stress_test.py](/mnt/c/1Jonathan/CTFS/research-dir/whaley/scripts/stress_test.py). It discovers active challenges from `/challenges`, spawns synthetic team-owned instances through the admin API, generates mixed HTTP/TCP traffic, samples admin and PCAP status, and can optionally clean up the instances it created.

Quick smoke test:

```bash
pip install -r requirements.txt

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

Larger rehearsal:

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

Cleanup later from saved state:

```bash
WHALEY_BASE_URL=http://your-server:8000 \
WHALEY_ADMIN_KEY=your-admin-key \
python3 scripts/stress_test.py \
  --cleanup-from-state /tmp/whaley-stress.json
```

The full runbook, caveats for `AUTH_MODE=none`, and tuning guidance live in [DOCUMENTATION.md](DOCUMENTATION.md#-stress-testing).

---

## 📸 Screenshots

<table>
<tr>
<td align="center" width="50%">
<img src="images/image.png" alt="User Dashboard" />
<br><b>User Dashboard</b>
</td>
<td align="center" width="50%">
<img src="images/image-4.png" alt="Admin Dashboard" />
<br><b>Admin Dashboard &amp; Controls</b>
</td>
</tr>
<tr>
<td align="center">
<img src="images/image-5.png" alt="Event Logs" />
<br><b>Event Logs &amp; Audit Trail</b>
</td>
<td align="center">
<img src="images/image-6.png" alt="Challenge Manager" />
<br><b>Challenge Manager</b>
</td>
</tr>
<tr>
<td align="center">
<img src="images/image-7.png" alt="Dynamic Flags" />
<br><b>Dynamic Flags &amp; Suspicious Submissions</b>
</td>
<td align="center">
<img src="images/image-8.png" alt="CTFd Sync" />
<br><b>CTFd Sync Wizard</b>
</td>
</tr>
</table>

---

## ⚙️ Admin Settings & Challenge Management

### Live Settings (No Restart Required)

All key Whaley settings can be changed at runtime via the **Admin Panel → ⚙️ Settings** tab:

| Category | Settings |
|----------|----------|
| **Instance** | Timeout, max instances per user/team |
| **Resources** | Container max memory, CPU cores, PID limit |
| **Network** | Port range, isolation, subnet pool, public host |
| **Features** | Dynamic flags, flag prefix |
| **Authentication** | Auth mode (CTFd/None), CTFd URL, CTFd API key, local Admin Key fallback, metrics secret |
| **Forensics** | Auto capture, retention period |
| **Packet Capture** | Mode (all/selected/none), selected challenges, max file size, retention, snap length, BPF filter |

Changes persist to the database and survive container restarts—no need to edit `docker-compose.yaml` or `.env` files.

### Challenge Active/Inactive Toggle

Control which challenges are visible and spawnable from the **Challenge Manager** tab:

- **🟢 Active** — Visible on the user dashboard, can be spawned
- **🔴 Inactive** — Hidden from users, spawn requests rejected (HTTP 403)

Use this during competitions to stage challenges for later rounds, or to quickly disable a broken challenge without deleting it.

Challenge uploads reject path traversal, absolute paths, and symlinks. Runtime challenge trees are also rejected if they contain symlinks. The browser editor only writes text files up to 2 MB, and Whaley blocks deleting a challenge while active instances are still using it.

### Public Challenge Links

Each challenge has a standalone public page at `/instance/{challenge_id}` showing just that challenge's details and a Spawn button — handy for sharing a direct link instead of the full catalog. The page loads the challenge through the existing authenticated `/challenges/{challenge_id}` endpoint and prompts for a CTFd token on `401`, same as the main dashboard.

- **Challenge Manager → Copy Link** — copies the public link for a challenge to your clipboard.
- **Dynamic Flags → Challenge ID Mapping → Sync Public Link to CTFd** — for challenges mapped to a CTFd challenge ID, pushes the public link into that challenge's CTFd `connection_info` field so players see it on the CTFd challenge page itself.

### Admin Instance Operations

The admin dashboard can manually spawn instances for a chosen user/team owner, force-destroy any active instance, inspect live per-instance Docker logs, and sample detailed resource metrics on demand. The Monitoring tab now uses a cheap host-level snapshot by default, so it stays usable even when hundreds of instances are alive, and it also shows firewall/rate-limit status plus per-instance rule details. The Packet Capture tab adds per-instance flow summaries, payload search, raw PCAP downloads, and retention cleanup controls. Failed spawn/stop actions return the backend error message directly in the UI, which makes broken compose files, resource exhaustion, firewall misconfiguration, and Docker cleanup issues easier to diagnose during an event.

### Enforced Resource Limits

Whaley enforces maximum resource limits on **every** container, regardless of what the challenge's `docker-compose.yaml` specifies:

```
CONTAINER_MAX_MEMORY=384m    # Caps mem_limit in compose files
CONTAINER_MAX_CPU=0.5        # Caps cpus in compose files
CONTAINER_PIDS_LIMIT=256     # Injects pids_limit (fork bomb protection)
```

Per-challenge overrides can be set via the admin API if certain challenges need more resources.

---

## 📖 Documentation

For comprehensive documentation, see **[DOCUMENTATION.md](DOCUMENTATION.md)**:

- 🔧 [Installation & Configuration](DOCUMENTATION.md#installation)
- 📦 [Challenge Structure & Examples](DOCUMENTATION.md#challenge-structure)
- 🔌 [API Reference](DOCUMENTATION.md#api-reference)
- 🛡️ [Security Considerations](DOCUMENTATION.md#security)
- 📈 [Instance Forensics](DOCUMENTATION.md#instance-forensics)
- 📡 [Native Packet Capture](DOCUMENTATION.md#-native-packet-capture)
- 🔍 [Resource Monitoring](DOCUMENTATION.md#resource-monitoring)
- 📡 [Prometheus Metrics](DOCUMENTATION.md#prometheus-metrics)
- 📊 [Capacity Planning](DOCUMENTATION.md#capacity-planning)
- 🧪 [Stress Testing](DOCUMENTATION.md#-stress-testing)
- ⚙️ [Admin Settings & Challenge Management](DOCUMENTATION.md#admin-settings)

<img width="auto" height="auto" alt="Screenshot 2026-07-18 181915" src="https://github.com/user-attachments/assets/c04887dd-30e4-4250-858f-054992085e73" />

**Wreck IT 7.0 Post-Event Technical Note**: During Wreck IT 7.0 (~7-8 challenges, ~2K spawn activity), Whaley's PCAP capture was configured to sniff traffic on every active challenge instance (PCAP_MODE=all), and the periodic background job that compresses rotated capture files every ~10 minutes generated sustained disk I/O spikes (write-heavy, up to ~50 MiB/s) that degraded the instancer's web interface responsiveness and occasionally caused lock-acquisition timeouts on instance actions under load; for future events, PCAP capture should be scoped to selected challenges only (PCAP_MODE=selected / PCAP_SELECTED_CHALLENGES) rather than capturing all instances, to keep this I/O overhead proportional to what's actually needed for forensics.

<img width="auto" height="auto" alt="image" src="https://github.com/user-attachments/assets/9eb98352-9829-40d9-bd4b-29f56c7614f1" />


---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Ideas for Contribution

- 🐛 Bug fixes and improvements
- 📝 Documentation enhancements
- 🎨 UI/UX improvements
- 🧪 Test coverage
- 🌐 Internationalization

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

Some infrastructure ideas and hardening lessons for Whaley were inspired by the MCTF 5.0 post-mortem and follow-up work from [MCTF Behind the Scenes: The Infra We Built and the Chaos We Caused](https://mctf-blog.microclub.info/posts/organizing-mctf-infrastructure), by [Younes Ferradji (Ynxfdj)](https://github.com/Younesfdj) and [Abderrahmane Yahiaoui (COn4n)](https://github.com/Abdo30004).

The packet-capture workflow and PCAP sidecar direction were also inspired by [Tulip](https://github.com/OpenAttackDefenseTools/tulip).

---

## 👨‍💻 Author

<table>
<tr>
<td align="center">
<a href="https://github.com/jonscafe">
<img src="https://github.com/jonscafe.png" width="100px" alt="keii" style="border-radius: 50%"/>
<br />
<b>keii</b>
</a>
<br />
<sub>Creator & Maintainer</sub>
</td>
</tr>
</table>

---

<p align="center">
Built with ❤️ for the CTF community
<br><br>
<b>If you find Whaley useful, please consider giving it a ⭐</b>
<br><br>
<a href="https://github.com/jonscafe/whaley">
<img src="https://img.shields.io/github/stars/jonscafe/whaley?style=social" alt="GitHub stars">
</a>
</p>
