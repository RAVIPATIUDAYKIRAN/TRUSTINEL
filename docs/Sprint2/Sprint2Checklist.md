# TRUSTINEL - Sprint 2 Implementation Checklist

This checklist tracks the tasks required to implement Sprint 2 according to the approved designs.

---

## 🗄 1. Database & Alembic Setup
- [ ] Implement base SQLAlchemy models in `app/models/scan.py`:
  - [ ] `WebsiteScan` ORM model.
  - [ ] `TrustReport` ORM model with `scan_id` unique foreign key.
  - [ ] `ScanHistory` ORM model with `scan_id` foreign key.
- [ ] Export all models in `app/models/__init__.py` to ensure Alembic autogenerates successfully.
- [ ] Import models in `alembic/env.py` under `target_metadata`.
- [ ] Run migration command: `alembic revision --autogenerate -m "create_sprint2_tables"`.
- [ ] Review migration scripts in `alembic/versions/` for accuracy.
- [ ] Apply migration: `alembic upgrade head`.

---

## 🏗 2. Repository Layer
- [ ] Create `app/repositories/scan.py` implementing `ScanRepository`:
  - [ ] `create_scan(url, domain, status)`: Writes to `website_scans` table.
  - [ ] `get_scan_by_id(scan_id)`: Fetches a scan by UUID and eager-loads `trust_report`.
  - [ ] `save_trust_report(scan_id, score, risk_level, summary)`: Writes to `trust_reports`.
  - [ ] `update_scan_status(scan_id, status)`: Modifies state of target scan.
  - [ ] `create_history_log(scan_id, action, status)`: Logs entry to `scan_history`.

---

## ⚙ 3. Service Layer & Decoupled Engine
- [ ] Create `app/services/generator.py`:
  - [ ] Define abstract base class interface `TrustReportGenerator`.
  - [ ] Implement subclass `MockTrustReportGenerator(TrustReportGenerator)` returning:
    - [ ] Score `25`/`DANGEROUS` if domain contains suspicious keywords.
    - [ ] Score `85`/`SAFE` for general hostnames.
- [ ] Create `app/services/scan.py` implementing `ScanService`:
  - [ ] Inject `ScanRepository` and `TrustReportGenerator` dependencies.
  - [ ] Implement `initiate_scan(url: str)` coordinating scan initiation, history logging, calling generator, saving report, and updating status in a database transaction block.
  - [ ] Implement `get_scan(scan_id: UUID)` pulling data from repository.

---

## 🎛 4. Validation Schemas & API Endpoints
- [ ] Create `app/schemas/scan.py`:
  - [ ] `ScanCreateRequest`: Uses `AnyHttpUrl` validation.
  - [ ] `ScanResponse` and `TrustReportDetails` models formatted to spec.
- [ ] Create `app/api/v1/scan.py` defining FastAPI routers:
  - [ ] `POST /api/v1/scan`: Triggers scan service.
  - [ ] `GET /api/v1/scan/{id}`: Fetches scan results.
- [ ] Wire up routers in `app/main.py`.

---

## 🧪 5. Verification & Testing
- [ ] Spin up Docker Compose and run database migrations.
- [ ] Send `POST /api/v1/scan` request with valid URL; verify response status `201` and mock trust report attributes.
- [ ] Send `POST /api/v1/scan` request with malformed URL; verify response status `422` and JSON schema validation details.
- [ ] Send `GET /api/v1/scan/{id}` request with generated scan ID; verify response status `200` matches payload format.
- [ ] Send `GET /api/v1/scan/{id}` request with invalid UUID; verify response status `404`.
