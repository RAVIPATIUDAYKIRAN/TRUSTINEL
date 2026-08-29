// TRUSTINEL API Client
// Single source of truth for backend communication

const API_BASE_URL = "http://127.0.0.1:8000";

export interface AIEvidenceMapping {
  category: "SSL" | "WHOIS" | "SECURITY_HEADERS" | "REDIRECTS" | "DETERMINISTIC_TRUST" | string;
  finding: string;
  impact: string;
}

export interface AIThreatAnalysisResult {
  enabled: boolean;
  threat_level: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
  confidence: number;
  suspicious_indicators: string[];
  reasoning: string;
  recommended_action: string;
  evidence_mappings: AIEvidenceMapping[];
}

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
  ai_threat_analysis?: AIThreatAnalysisResult | null;
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
    public statusCode?: number,
    public errorCode?: string,
    public retryAfterSeconds?: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function handleResponseError(response: Response): Promise<never> {
  let detail = `Server returned status ${response.status}`;
  let errorCode: string | undefined;
  let retryAfterSeconds: number | undefined;

  // Extract Retry-After header if present
  const retryHeader = response.headers.get("Retry-After");
  if (retryHeader) {
    const parsed = parseInt(retryHeader, 10);
    if (!isNaN(parsed) && parsed > 0) {
      retryAfterSeconds = parsed;
    }
  }

  try {
    const body = await response.json();
    if (body.detail) {
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    }
    if (body.error_code) {
      errorCode = String(body.error_code);
    }
    if (body.retry_after_seconds && typeof body.retry_after_seconds === "number") {
      retryAfterSeconds = body.retry_after_seconds;
    }
  } catch {
    /* Ignore JSON parse errors */
  }

  // Friendly error messages based on status codes
  if (response.status === 400 && errorCode === "INVALID_URL") {
    detail = detail || "Invalid website URL format provided.";
  } else if (response.status === 403 && errorCode === "URL_NOT_ALLOWED") {
    detail = detail || "Scanning restricted host or internal network destination is not allowed.";
  } else if (response.status === 429) {
    const secondsText = retryAfterSeconds ? ` Please try again in ${retryAfterSeconds} seconds.` : "";
    detail = `Rate limit exceeded.${secondsText}`;
  } else if (response.status === 503) {
    detail = "TRUSTINEL backend services are currently undergoing maintenance. Please try again shortly.";
  }

  throw new ApiError(detail, response.status, errorCode, retryAfterSeconds);
}

export async function scanWebsite(url: string): Promise<ScanResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("Request timed out waiting for analysis server response.");
    }
    throw new ApiError("Could not reach the TRUSTINEL analysis server. Is the backend running?");
  }
  clearTimeout(timeoutId);

  if (!response.ok) {
    await handleResponseError(response);
  }

  try {
    return (await response.json()) as ScanResponse;
  } catch {
    throw new ApiError("Received an invalid response format from the server.");
  }
}

export async function getScan(scanId: string): Promise<ScanResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scan/${scanId}`, {
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("Request timed out waiting for analysis server response.");
    }
    throw new ApiError("Could not reach the TRUSTINEL analysis server. Is the backend running?");
  }
  clearTimeout(timeoutId);

  if (!response.ok) {
    await handleResponseError(response);
  }

  try {
    return (await response.json()) as ScanResponse;
  } catch {
    throw new ApiError("Received an invalid response format from the server.");
  }
}
