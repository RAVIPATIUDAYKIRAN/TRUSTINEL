# TRUSTINEL - Sprint 2 Folder Changes

This document maps the structural additions to the `backend/` component of the project directory during the implementation of Sprint 2.

---

## 📂 Structural Additions

```text
backend/
├── app/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── __init__.py           # [NEW] Exports V1 endpoint routers
│   │   │   └── scan.py               # [NEW] Scan routing controller (POST /scan, GET /scan/{id})
│   │   └── __init__.py               # [NEW] Sets up core base API Router prefixing v1
│   │
│   ├── models/
│   │   ├── __init__.py               # [NEW] Exports ORM Models
│   │   └── scan.py                   # [NEW] ORM definitions (WebsiteScan, TrustReport, ScanHistory)
│   │
│   ├── schemas/
│   │   ├── __init__.py               # [NEW] Exports Pydantic Validation Models
│   │   └── scan.py                   # [NEW] Schemas (ScanCreateRequest, ScanResponse, TrustReportDetails)
│   │
│   ├── repositories/
│   │   ├── __init__.py               # [NEW] Exports Repositories
│   │   └── scan.py                   # [NEW] Database operations (ScanRepository)
│   │
│   ├── services/
│   │   ├── __init__.py               # [NEW] Exports Services
│   │   ├── scan.py                   # [NEW] ScanService (orchestrates scans)
│   │   └── generator.py              # [NEW] TrustReportGenerator interface & MockTrustReportGenerator
│   │
│   └── main.py                       # [MODIFY] Register v1 router in FastAPI app instance
│
├── alembic/
│   └── versions/
│       └── <hash>_sprint2_initial.py # [NEW] Alembic initial migration for website_scans, trust_reports, scan_history
│
docs/
└── Sprint2/
    ├── Sprint2_PRD.md                # [NEW] Requirements definition
    ├── DatabaseDesign.md             # [NEW] Database schemas
    ├── ERDiagram.md                  # [NEW] Database entity relations
    ├── APIContracts.md               # [NEW] Endpoint specifications
    ├── ServiceFlow.md                # [NEW] Decoupled lifecycle steps
    ├── FolderChanges.md              # [NEW] Folder mappings (This file)
    └── Sprint2Checklist.md           # [NEW] QA/Implementation checklist
```
