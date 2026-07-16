# TRUSTINEL - Sprint 2 Product Requirements Document (PRD)

## 1. Sprint Objective
The primary objective of Sprint 2 is to construct the backend pipeline foundation. This involves connecting the controller layers, data validation schemas, services, and repositories to PostgreSQL, proving the end-to-end data flow using a **Mock Trust Report Generator** without any analytics or intelligence algorithms.

## 2. Functional Scope
- **URL Scanning Trigger**: Allow users to request a trust assessment for any web URL.
- **Mock Trust Report Generation**: Automatically generate a deterministic mock trust score and risk classification.
- **Audit/Scan History**: Record all scanning transactions for tracking and audit logs.
- **Decoupled Architecture**: Maintain clear boundaries between endpoints, services, external generator engines, repositories, and ORM models.

## 3. Out of Scope (Strict Exclusions for Sprint 2)
- **Trust Scores / Rules**: No SSL version checkers, WHOIS record analysis, domain length rules, keyword list evaluations, or TLD analysis.
- **External API Integrations**: No integration with VirusTotal, Google Safe Browsing, or external intelligence APIs.
- **AI Integrations**: No Gemini, OpenAI, or machine learning model hookups.
- **Scraping / Crawling**: No fetching or downloading target web pages or headers.
- **Browser Scripting**: No real-time integration into browser history, tab events, or content listeners beyond simple manual triggering.
- **Authentication**: No user login, OAuth, session management, or registration.

## 4. Key Deliverables
- Fully designed database schema with exactly three tables: `website_scans`, `trust_reports`, and `scan_history`.
- Two core endpoints:
  - `POST /api/v1/scan`
  - `GET /api/v1/scan/{id}`
- Decoupled `TrustReportGenerator` interface yielding simulated outputs.

## 5. Acceptance Criteria
- Triggering a scan returns a `201 Created` with a unique scan UUID and mock trust scores.
- Querying a scan ID returns a `200 OK` containing full details of the scan, its generated trust report, and its timestamps.
- Non-conforming URLs return a `422 Unprocessable Entity` validation error.
- Internal service failures trigger standardized JSON error payloads.
- Database records are successfully written to target PostgreSQL tables.
