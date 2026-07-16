# TRUSTINEL - Sprint 2 Service Flow

This document details the decoupled execution flow for website trust scans. The layers are split following Clean Architecture principles to keep components future-proof.

---

## 🔄 Service Architecture Overview

```mermaid
sequenceDiagram
    autonumber
    actor Client as Browser Extension
    participant API as FastAPI Router
    participant Validate as Pydantic Schema
    participant Service as Scan Service
    participant Engine as Trust Report Generator (Mock)
    participant Repo as Scan Repository
    database DB as PostgreSQL DB

    Client->>API: POST /api/v1/scan (url)
    API->>Validate: Parse and validate request
    alt Invalid URL
        Validate-->>API: ValidationError exception
        API-->>Client: 422 Unprocessable Entity
    else Valid URL
        Validate->>API: Validated URL string
    end
    
    API->>Service: initiate_scan(url)
    
    Service->>Repo: create_scan(url, domain, status="PENDING")
    Repo->>DB: INSERT INTO website_scans
    DB-->>Repo: website_scan record (id, status)
    
    Service->>Repo: create_history_log(scan_id, action="SCAN_INITIATED")
    Repo->>DB: INSERT INTO scan_history
    
    Service->>Engine: generate_trust_report(scan_id, domain)
    Note over Engine: Generates deterministic mock score,<br/>risk level, and summary
    Engine-->>Service: Mock trust report data
    
    Service->>Repo: save_trust_report(scan_id, score, risk_level, summary)
    Repo->>DB: INSERT INTO trust_reports
    
    Service->>Repo: update_scan_status(scan_id, status="COMPLETED")
    Repo->>DB: UPDATE website_scans SET status="COMPLETED"
    
    Service->>Repo: create_history_log(scan_id, action="REPORT_GENERATED")
    Repo->>DB: INSERT INTO scan_history
    
    Service-->>API: website_scan aggregate details
    API-->>Client: 201 Created (JSON Response with report)
```

---

## 🛠 Layer Responsibilities

### 1. Controller Layer (`FastAPI Router`)
- Catches the incoming HTTP POST request.
- Manages routing, serialization, CORS filters, and yields dependency-injected services.

### 2. Validation Layer (`Pydantic Schemas`)
- Validates structural shapes.
- Extracts host/domain values automatically from target URL string structures during parse steps.

### 3. Service Layer (`Scan Service`)
- Orchestrates transactional flow.
- Fetches database representations from repository layers and forwards details to the Generator interface.
- Devoid of intelligence/rule evaluation checks.

### 4. Decoupled Interface (`Trust Report Generator`)
- An abstract/interface base class defined in service layer interfaces.
- **Sprint 2 Implementation**: Implemented by `MockTrustReportGenerator` which outputs deterministic mock metadata:
  - Domain containing "suspicious" -> score: `25`, risk: `DANGEROUS`, summary: `Domain contains blacklisted/flagged keywords.`
  - Other domains -> score: `85`, risk: `SAFE`, summary: `Domain format and extension verified successfully.`
- **Sprint 3 Implementation (Future)**: The Mock class will be replaced with `TrustIntelligenceGenerator` importing rule checks, SSL tests, and WHOIS scrapers, without altering any methods in `Scan Service` or `Repository`.

### 5. Repository Layer (`Scan Repository`)
- Wraps database calls using async SQLAlchemy.
- Handles reading/writing ORM structures and transactional commits.
