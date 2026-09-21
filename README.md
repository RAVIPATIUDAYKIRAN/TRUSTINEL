# TRUSTINEL — Universal Real-Time Website Trust & Fraud Risk Engine

## About
TRUSTINEL is a multi-dimensional real-time trust assessment platform and Chrome Extension designed to detect website scam/fraud indicators, fake e-commerce stores, credential harvesting, phishing, and technical security risks.

## Core Security & Architecture Principles

1. **TECHNICAL SECURITY != SCAM LEGITIMACY**
   Valid SSL/TLS certificates and HTTP security headers prove transport encryption, **not** commercial trustworthiness or legitimate intent.
2. **DETERMINISTIC VERDICT ENGINE IS AUTHORITATIVE**
   Scam risk detection is governed by `RuleBasedTrustEngine` and `RiskAggregationEngine`. AI is an **explanatory layer only** and cannot override or fabricate risk scores.
3. **HONEST UNCERTAINTY & UNKNOWN SEMANTICS**
   Missing or unavailable intelligence is explicitly reported as `UNKNOWN` / `UNAVAILABLE`. Unknown status is **never** silently treated as 100% safe.
4. **RENDERED DOM AUTHORITATIVE**
   The Chrome extension captures bounded live browser-rendered DOM (`document.documentElement.cloneNode(true)`), redacting sensitive input values, text nodes, and attributes before analysis.
5. **ZERO HARDCODING & ZERO FABRICATION**
   Scam logic is 100% domain-agnostic with zero domain/brand hardcoding and zero test-site specific overrides.

---

## Folder Structure
```text
TRUSTINEL/
│
├── backend/
│   ├── app/
│   │   ├── api/           # Endpoints/routes definitions
│   │   ├── core/          # Loggers, SSRF validators, rate limiters
│   │   ├── config/        # Environment and app configuration
│   │   ├── middleware/    # Exceptions and interceptors
│   │   ├── services/      # Business logic (ScanService, RiskAggregationEngine)
│   │   ├── repositories/  # Database data-access layer
│   │   ├── models/        # SQLAlchemy Models (ORM)
│   │   ├── schemas/       # Pydantic Schemas
│   │   └── main.py        # Application entry point
│   │
│   ├── tests/             # Comprehensive pytest regression suite (379 tests)
│   ├── alembic/           # Alembic database migrations
│   ├── pyproject.toml     # uv configuration & dependency list
│   └── Dockerfile         # Backend production container definition
│
├── extension/
│   ├── popup/             # React Popup UI components
│   ├── background/        # Service Worker scripts & path-aware cache
│   ├── content/           # Content scripts & Shadow DOM indicator
│   ├── manifest.json      # Chrome Manifest V3 configuration (strict CSP)
│   └── package.json       # Extension package & Vite build setup
│
├── deployment/
│   ├── docker-compose.prod.yml    # Isolated production container compose
│   └── production.env.example     # Environment template for production
│
├── docker-compose.yml     # Local development compose setup
└── README.md              # Project documentation
```

---

## How to Run

### Development Environment
```bash
# Start backend and database services
docker-compose up --build

# Run backend test suite
cd backend
PYTHONPATH=. uv run pytest tests/ -v
```

### Production Deployment
```bash
# Navigate to deployment directory and configure secrets
cd deployment
cp production.env.example .env

# Start isolated production stack
docker-compose -f docker-compose.prod.yml up -d
```

### Loading Chrome Extension
```bash
cd extension
npm ci
npm run build
```
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select `extension/dist`.

---

## Production Security Controls

- **XSS Prevention**: Shadow DOM dynamic indicator renders user-facing text safely using DOM APIs (`textContent` / `createElement`).
- **SSRF Protection**: `URLSecurityValidator` blocks loopback, private IPv4/IPv6, link-local, CGNAT (100.64.0.0/10), metadata IPs (169.254.169.254), and performs DNS resolution checks.
- **Privacy Redaction**: `getRedactedRenderedDom()` redacts passwords, card numbers, CVVs, emails, contenteditables, and authorization attributes.
- **CORS Hardening**: Production mode enforces strict origin allowlists and disables wildcard extension regex.
- **Least Privilege Manifest**: Extension uses minimal permissions (`activeTab`, `storage`, `scripting`, `sidePanel`) and strict Manifest V3 CSP (`script-src 'self'`).
