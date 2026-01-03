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

// Request timeout in milliseconds
const REQUEST_TIMEOUT = 30000; // 30 seconds

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
  
  // Chat endpoints
  chat: `${API_BASE_URL}/chat`,
  chatTips: `${API_BASE_URL}/chat/tips`,
  
  // Community endpoints
  communityReport: `${API_BASE_URL}/community/report`,
  communityReports: `${API_BASE_URL}/community/reports`,
  communityWarning: `${API_BASE_URL}/community/warning`,
  
  // Other endpoints
  report: `${API_BASE_URL}/report`,
  reports: `${API_BASE_URL}/reports`,
  feedback: `${API_BASE_URL}/feedback`,
  feedbackStats: `${API_BASE_URL}/feedback/stats`,
  
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

// API Error class for better error handling
export class ApiError extends Error {
  public readonly statusCode: number;
  public readonly errorType: string;
  public readonly isTimeout: boolean;
  public readonly isNetworkError: boolean;
  public readonly isRateLimited: boolean;

  constructor(
    message: string,
    statusCode: number = 0,
    errorType: string = "unknown",
    { isTimeout = false, isNetworkError = false } = {}
  ) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.errorType = errorType;
    this.isTimeout = isTimeout;
    this.isNetworkError = isNetworkError;
    this.isRateLimited = statusCode === 429;
  }
}

// Get user-friendly error message
export function getErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.isTimeout) {
      return "Request timed out. Please try again.";
    }
    if (error.isNetworkError) {
      return "Unable to connect to server. Please check your connection.";
    }
    if (error.isRateLimited) {
      return "Too many requests. Please wait a moment before trying again.";
    }
    if (error.statusCode === 400) {
      return error.message || "Invalid input. Please check your data.";
    }
    if (error.statusCode === 422) {
      return error.message || "Could not process the request.";
    }
    if (error.statusCode >= 500) {
      return "Server error. Please try again later.";
    }
    return error.message;
  }
  
  if (error instanceof Error) {
    return error.message;
  }
  
  return "An unexpected error occurred.";
}

// Create AbortController with timeout
function createTimeoutController(timeoutMs: number = REQUEST_TIMEOUT): { 
  controller: AbortController; 
  timeoutId: ReturnType<typeof setTimeout>;
} {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  return { controller, timeoutId };
}

// Helper function to make API requests with proper error handling
export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const { controller, timeoutId } = createTimeoutController();
  
  try {
    const response = await fetch(endpoint, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let errorMessage = `API Error: ${response.status}`;
      let errorType = "http_error";
      
      try {
        const errorData = await response.json();
        errorMessage = errorData.detail || errorData.error?.message || errorMessage;
        errorType = errorData.error?.type || errorType;
      } catch {
        // Ignore JSON parsing errors
      }
      
      throw new ApiError(errorMessage, response.status, errorType);
    }

    return response.json();
  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error instanceof ApiError) {
      throw error;
    }
    
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("Request timed out", 0, "timeout", { isTimeout: true });
    }
    
    if (error instanceof TypeError && error.message.includes("fetch")) {
      throw new ApiError("Network error", 0, "network_error", { isNetworkError: true });
    }
    
    throw new ApiError(
      error instanceof Error ? error.message : "Unknown error occurred"
    );
  }
}

// Helper for multipart form data (file uploads) with proper error handling
export async function apiUpload<T>(
  endpoint: string,
  formData: FormData
): Promise<T> {
  const { controller, timeoutId } = createTimeoutController(60000); // 60 second timeout for uploads
  
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let errorMessage = `Upload Error: ${response.status}`;
      let errorType = "upload_error";
      
      try {
        const errorData = await response.json();
        errorMessage = errorData.detail || errorData.error?.message || errorMessage;
        errorType = errorData.error?.type || errorType;
      } catch {
        // Ignore JSON parsing errors
      }
      
      throw new ApiError(errorMessage, response.status, errorType);
    }

    return response.json();
  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error instanceof ApiError) {
      throw error;
    }
    
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("Upload timed out", 0, "timeout", { isTimeout: true });
    }
    
    if (error instanceof TypeError && error.message.includes("fetch")) {
      throw new ApiError("Network error", 0, "network_error", { isNetworkError: true });
    }
    
    throw new ApiError(
      error instanceof Error ? error.message : "Unknown error occurred"
    );
  }
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
