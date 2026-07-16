# TRUSTINEL - Sprint 2 API Contracts

This document specifies the REST API endpoints exposed by the backend during Sprint 2.

---

## 📡 Endpoints

### 1. Initiate Scan
Trigger a trust scan for a target website.

- **Endpoint**: `/api/v1/scan`
- **Method**: `POST`
- **Headers**:
  - `Content-Type: application/json`

#### Request Body
```json
{
  "url": "https://example-suspicious-site.com/path?query=1"
}
```
- **Validation Rules**:
  - `url`: Must be a valid HTTP/HTTPS URL syntax (validated via Pydantic AnyHttpUrl string). String length between 1 and 2048. Not empty.

#### Response Body (`201 Created`)
```json
{
  "id": "e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21",
  "url": "https://example-suspicious-site.com/path?query=1",
  "domain": "example-suspicious-site.com",
  "status": "COMPLETED",
  "created_at": "2026-07-16T18:40:00Z",
  "trust_report": {
    "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "trust_score": 85,
    "risk_level": "SAFE",
    "summary": "Mock Assessment: Domain length and format match expected patterns.",
    "generated_at": "2026-07-16T18:40:01Z"
  }
}
```

---

### 2. Get Scan Details
Retrieve the status and results of a scan execution by its UUID.

- **Endpoint**: `/api/v1/scan/{id}`
- **Method**: `GET`
- **Path Parameters**:
  - `id` (UUID): The unique ID returned during scan creation.

#### Response Body (`200 OK`)
```json
{
  "id": "e93f8e6c-7f24-4f05-83e3-78b1d9bf5b21",
  "url": "https://example-suspicious-site.com/path?query=1",
  "domain": "example-suspicious-site.com",
  "status": "COMPLETED",
  "created_at": "2026-07-16T18:40:00Z",
  "updated_at": "2026-07-16T18:40:02Z",
  "trust_report": {
    "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "trust_score": 85,
    "risk_level": "SAFE",
    "summary": "Mock Assessment: Domain length and format match expected patterns.",
    "generated_at": "2026-07-16T18:40:01Z"
  }
}
```

---

## 🛑 Error Responses

### `422 Unprocessable Entity` (Validation Error)
Triggered when request payload fails validation (e.g. malformed URL scheme).
```json
{
  "detail": "Validation error",
  "errors": [
    {
      "loc": ["body", "url"],
      "msg": "invalid or missing URL scheme",
      "type": "value_error.url.scheme"
    }
  ],
  "error_code": "VALIDATION_ERROR",
  "status_code": 422
}
```

### `404 Not Found`
Triggered when requesting a scan ID that does not exist.
```json
{
  "detail": "Scan with ID e93f8e6c-7f24-4f05-83e3-78b1d9bf5b99 not found",
  "error_code": "NOT_FOUND",
  "status_code": 404
}
```

### `500 Internal Server Error`
Triggered on unhandled backend exceptions.
```json
{
  "detail": "An internal server error occurred.",
  "error_code": "INTERNAL_SERVER_ERROR",
  "status_code": 500
}
```
