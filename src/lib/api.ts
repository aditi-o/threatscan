/**
 * API Configuration for SafeLink Shield
 * 
 * Switch between environments by changing API_ENV:
 * - "local": Development server at localhost:8000
 * - "production": Your deployed backend URL
 */

type ApiEnvironment = "local" | "production";

// ===========================================
// CHANGE THIS TO SWITCH ENVIRONMENTS
// ===========================================
const API_ENV: ApiEnvironment = "local";

// Environment URLs
const API_URLS: Record<ApiEnvironment, string> = {
  local: "http://localhost:8000",
  production: "https://your-production-api.com", // Update this with your production URL
};

// Export the current API base URL
export const API_BASE_URL = API_URLS[API_ENV];

// API Endpoints
export const API_ENDPOINTS = {
  // Scan endpoints
  scanUrl: `${API_BASE_URL}/scan/url`,
  scanText: `${API_BASE_URL}/scan/text`,
  scanScreenshot: `${API_BASE_URL}/scan/screenshot`,
  scanAudio: `${API_BASE_URL}/scan/audio`,
  
  // Auth endpoints
  signup: `${API_BASE_URL}/auth/signup`,
  login: `${API_BASE_URL}/auth/login`,
  me: `${API_BASE_URL}/auth/me`,
  
  // Other endpoints
  chat: `${API_BASE_URL}/chat`,
  report: `${API_BASE_URL}/report`,
  reports: `${API_BASE_URL}/reports`,
  
  // Health check
  health: `${API_BASE_URL}/health`,
};

// Type definitions for API responses
export interface ScanResult {
  input_type: string;
  input_text: string;
  risk_score: number;
  label: string;
  is_safe: boolean;
  reasons: string[];
  suggestions: string[];
  model_version: string;
  scan_id?: number;
}

export interface ScreenshotScanResult extends ScanResult {
  extracted_text: string;
}

export interface AudioScanResult extends ScanResult {
  transcript: string;
}

// Helper function to make API requests
export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(endpoint, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `API Error: ${response.status}`);
  }

  return response.json();
}

// Helper for multipart form data (file uploads)
export async function apiUpload<T>(
  endpoint: string,
  formData: FormData
): Promise<T> {
  const response = await fetch(endpoint, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Upload Error: ${response.status}`);
  }

  return response.json();
}

// Check if backend is available
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const response = await fetch(API_ENDPOINTS.health, { 
      method: "GET",
      signal: AbortSignal.timeout(3000) // 3 second timeout
    });
    return response.ok;
  } catch {
    return false;
  }
}
