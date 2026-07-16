# TRUSTINEL - Decision Log

This document records the foundational technical decisions made during the design and bootstrap of **TRUSTINEL**.

## Decisions

### 1. Choice of Package Manager for Backend: `uv`
- **Context**: Traditionally, Python projects use `pip` with `requirements.txt` or `Pipenv`/`Poetry`.
- **Decision**: Adopt Astral's `uv` tool for package and project management (`pyproject.toml` and `uv.lock`).
- **Rationale**:
  - Extremely fast package resolution and installation.
  - Standardized modern Python package configuration using `pyproject.toml`.
  - Produces a deterministic `uv.lock` for reproducible builds.

### 2. Multi-stage Docker Builds with `uv`
- **Context**: Dockerizing the FastAPI backend with minimal footprint and maximum build speed.
- **Decision**: Use a multi-stage `Dockerfile` with Alpine and `ghcr.io/astral-sh/uv` to install dependencies, compiling only runtime libraries, and omitting build-time tools from the final runner container.
- **Rationale**: Keeps image size small and secures production containers by excluding compiler utilities.

### 3. Folder Structure Partitioning
- **Context**: Need a scalable structure supporting Clean Architecture / Modular Monolith patterns.
- **Decision**: Partition backend app into specific responsibility-based directories:
  - `config/`: Configuration parsing (`pydantic-settings`).
  - `core/`: Logging, deps, and shared backend utils.
  - `middleware/`: Exceptions and handlers.
  - `database/`: Connections and session setup.
  - `api/`, `services/`, `repositories/`, `models/`, `schemas/`, `ai/`, `utils/`: Clean separation of API layer, logic, ORM, validation, external client wrappers.
- **Rationale**: Standardizes where features go, enabling isolated additions as development scales.

### 4. Chrome Extension Build Setup with Vite
- **Context**: Structuring the Chrome Extension with React, TypeScript, and Tailwind CSS.
- **Decision**: Use Vite for bundling. Setup multi-input configuration in `vite.config.ts` to output distinct entry points:
  - `popup/index.html` -> Popup UI
  - `background/background.ts` -> Background service worker (`background.js`)
  - `content/content.ts` -> Content script injected into host pages (`content.js`)
- **Rationale**: Vite compiles assets rapidly and supports hot-module reloading during extension UI tweaking.

### 5. Minimal Permissions on Manifest V3
- **Context**: Security audit standards require asking only for needed privileges.
- **Decision**: Limit permissions to:
  - `activeTab`: To get details of the current tab.
  - `storage`: To store scanning history or extension preferences.
- **Rationale**: Adheres to the principle of least privilege, preventing security alerts in Chrome.

### 6. Health Check Design
- **Context**: Application health checking must prove that critical database and cache engines are ready.
- **Decision**: Health endpoint `/health` performs a query ping (`SELECT 1`) on PostgreSQL and a client ping (`PING`) on Redis asynchronously.
- **Rationale**: Ensures robust checks for database & Redis readiness, not just checking if the HTTP server is running.
