# TRUSTINEL

## About
TRUSTINEL is a next-generation real-time trust assessment platform designed to evaluate and verify online resources, ensuring a safer browsing environment.

## Mission
Our mission is to build trust on the web by providing transparent, instant, and reliable website scan results and scores to protect users from malicious content, scams, and misinformation.

## Architecture
TRUSTINEL is built as a **Modular Monolith** using **Clean Architecture** principles.
- **Frontend / Extension**: A Chrome Extension (Manifest V3) built with React, TypeScript, Tailwind CSS, and Vite.
- **Backend**: A high-performance async API built with Python 3.12, FastAPI, and SQLAlchemy.
- **Infrastructure**: Managed and containerized with Docker, featuring PostgreSQL for persistent storage and Redis for caching.

## Folder Structure
```text
TRUSTINEL/
│
├── backend/
│   ├── app/
│   │   ├── api/           # Endpoints/routes definitions
│   │   ├── core/          # Loggers, dependencies, middlewares
│   │   ├── config/        # Environment and app configuration
│   │   ├── middleware/    # Exceptions and interceptors
│   │   ├── services/      # Business logic (services)
│   │   ├── repositories/  # Database data-access layer
│   │   ├── models/        # SQLAlchemy Models (ORM)
│   │   ├── schemas/       # Pydantic Schemas
│   │   ├── database/      # DB session initialization
│   │   ├── ai/            # LLM / Gemini client skeletons
│   │   ├── utils/         # Helper functions
│   │   └── main.py        # Application entry point
│   │
│   ├── tests/             # Tests directory
│   ├── alembic/           # Alembic migrations directory
│   ├── pyproject.toml     # uv configuration & dependency list
│   ├── Dockerfile         # Backend container definition
│   └── .env.example       # Example environment configuration
│
├── extension/
│   ├── popup/             # React Popup files
│   ├── background/        # Service Worker scripts
│   ├── content/           # Content injection scripts
│   ├── assets/            # Extension static assets
│   ├── public/            # Chrome public resources
│   ├── manifest.json      # Chrome Manifest configuration
│   ├── package.json       # Node package manager configuration
│   ├── tsconfig.json      # TypeScript configurations
│   ├── vite.config.ts     # Vite builder setup
│   └── tailwind.config.js # Tailwind CSS styles setup
│
├── shared/                # Top-level directory for shared types/schemas
│
├── docs/                  # Project documentation files
│
├── deployment/            # Deployment configurations
│
├── scripts/               # Utility helper scripts
│
├── .github/               # CI/CD Workflows
│
├── docker-compose.yml     # Multi-container orchestrator configuration
├── README.md              # Project documentation overview
├── LICENSE                # License specifications
└── .gitignore             # Git ignored paths
```

## How to Run

### Development Environment (Docker Compose)
1. Copy the environment variables:
   ```bash
   cp backend/.env.example backend/.env
   ```
2. Build and run containers:
   ```bash
   docker compose up --build
   ```
3. Verify the services:
   - FastAPI Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
   - Health check: [http://localhost:8000/health](http://localhost:8000/health)

### Running Backend Locally
1. Install `uv` if not installed.
2. Initialize virtual environment and install dependencies:
   ```bash
   cd backend
   uv sync
   ```
3. Run the development server:
   ```bash
   uv run uvicorn app.main:app --reload
   ```

### Loading Chrome Extension
1. Install extension dependencies:
   ```bash
   cd extension
   npm install
   ```
2. Build the extension:
   ```bash
   npm run build
   ```
3. Open Google Chrome, navigate to `chrome://extensions/`.
4. Enable **Developer mode** (toggle in the top right).
5. Click **Load unpacked** and select the `extension/dist` folder.

## Tech Stack
- **Backend**: Python 3.12, FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis, uv
- **Extension**: Vite, React, TypeScript, Tailwind CSS, Manifest V3
- **DevOps**: Docker, Docker Compose, GitHub Actions

## Roadmap
- **Sprint 1**: Foundation & Development Environment (Completed)
- **Sprint 2**: Backend Core & Database Pipeline (Completed)
  - FastAPI REST APIs (`POST /api/v1/scan`, `GET /api/v1/scan/{id}`)
  - E2E Database integration (PostgreSQL) using SQLAlchemy 2.0 and Alembic migrations
  - Implementation of Clean Architecture with Repository and Service patterns
  - Timezone-aware metadata structures for Scans, Reports, and Audits
  - Decoupled Mock Trust Report Generator interface
  - Interactive OpenAPI documentation (Swagger UI / Redoc)
- **Sprint 3**: AI-powered Trust Assessment, Analysis Engines & UI Dashboard (Next)

