# TRUSTINEL — Production Deployment Guide

## Overview
This document describes the production deployment architecture, container topology, security hardening, database migration lifecycle, and health monitoring for the TRUSTINEL platform.

---

## Container Architecture Topology

```
                  +-----------------------------------+
                  |   Reverse Proxy (Nginx / Caddy)   |
                  |     HTTPS / TLS Termination       |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |     Backend Service (FastAPI)     |
                  |  Runs as non-root user: trustinel |
                  |  Port: 8000 | Health: /health     |
                  +--------+----------------+---------+
                           |                |
             +-------------+                +-------------+
             |                                            |
             v                                            v
+------------------------+                    +-----------------------+
|  PostgreSQL 16 Database|                    |  Redis 7 Cache        |
|  Port: 5432 (Internal) |                    |  Port: 6379 (Internal)|
+------------------------+                    +-----------------------+
```

---

## Deployment Prerequisites
- Docker Engine 24.0+
- Docker Compose v2+
- Domain name with SSL/TLS certificate configured on reverse proxy

---

## Step-by-Step Deployment Procedure

### 1. Environment Configuration
Copy the template to set your production secrets:
```bash
cp deployment/production.env.example .env
```
Edit `.env` and set:
- Strong database password in `DATABASE_URL`
- Production domain in `CORS_ORIGINS`
- Production AI provider API keys (if AI features are enabled)

### 2. Validate Docker Compose Configuration
```bash
docker compose config
```

### 3. Build & Launch Containers
```bash
docker compose build --no-cache
docker compose up -d
```

### 4. Verify Container Health & Non-Root Security
Check container execution status:
```bash
docker compose ps
```
Verify the backend process is running as non-root user `trustinel` (UID 10001):
```bash
docker compose exec backend id
```

### 5. Automated Database Migrations
Database schema migrations execute automatically on container startup via `backend/entrypoint.sh` using `alembic upgrade head`.

To run manual migration status checks:
```bash
docker compose exec backend alembic current
```

---

## Production Health Monitoring
Probe the health endpoint:
```bash
curl http://localhost:8000/health
```
Expected JSON Response:
```json
{
  "status": "healthy",
  "services": {
    "database": { "status": "connected" },
    "redis": { "status": "connected" }
  }
}
```

---

## Security Hardening Checklist
- [x] Non-root container user (`trustinel`, UID 10001)
- [x] Automated startup database migration execution
- [x] Native Docker health check probe (`HEALTHCHECK`)
- [x] Structured JSON logging (`LOG_FORMAT=json`)
- [x] Masked secret disclosure in health checks & log filters
- [x] Automated rate limiting (Post: 10/min, Get: 60/min)
- [x] SSRF URL validation and private IP blocking
