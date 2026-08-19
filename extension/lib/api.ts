// TRUSTINEL API Client
// Single source of truth for backend communication

const API_BASE_URL = "http://127.0.0.1:8000";

export interface TrustReport {
  id: string;
  scan_id: string;
  trust_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH";
  summary: string;
  generated_at: string;
  explanation: string | null;
  key_risks: string[];
  positive_signals: string[];
  recommendation: string | null;
}

export interface ScanResponse {
  id: string;
  url: string;
  domain: string;
  status: "PENDING" | "COMPLETED" | "FAILED";
  created_at: string;
  updated_at: string;
  trust_report: TrustReport | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function scanWebsite(url: string): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("Request was cancelled.");
    }
    throw new ApiError("Could not reach the TRUSTINEL analysis server. Is the backend running?");
  }

  if (!response.ok) {
    let detail = `Server returned ${response.status}`;
    try {
      const body = await response.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* ignore parse errors */ }
    throw new ApiError(detail, response.status);
  }

  try {
    return (await response.json()) as ScanResponse;
  } catch {
    throw new ApiError("Received an invalid response from the server.");
  }
}

export async function getScan(scanId: string): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scan/${scanId}`);
  } catch {
    throw new ApiError("Could not reach the TRUSTINEL analysis server. Is the backend running?");
  }

  if (!response.ok) {
    let detail = `Server returned ${response.status}`;
    try {
      const body = await response.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* ignore parse errors */ }
    throw new ApiError(detail, response.status);
  }

  try {
    return (await response.json()) as ScanResponse;
  } catch {
    throw new ApiError("Received an invalid response from the server.");
  }
}
