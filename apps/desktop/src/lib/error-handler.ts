/**
 * Error handling utilities for structured error responses
 *
 * This module provides utilities for parsing error responses from the backend
 * and checking for specific error codes programmatically.
 *
 * @module error-handler
 */

/**
 * Error codes enum matching the backend ErrorCode enum
 */
export const ErrorCode = {
  // Authentication errors
  AUTH_REQUIRED: "AUTH_REQUIRED",
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  INVALID_TOKEN: "INVALID_TOKEN",

  // Rate limiting errors
  RATE_LIMITED: "RATE_LIMITED",
  DEVICE_RATE_LIMITED: "DEVICE_RATE_LIMITED",
  GLOBAL_RATE_LIMITED: "GLOBAL_RATE_LIMITED",

  // Validation errors
  VALIDATION_ERROR: "VALIDATION_ERROR",
  INVALID_EMAIL: "INVALID_EMAIL",
  INVALID_PASSWORD: "INVALID_PASSWORD",
  PASSWORDS_DO_NOT_MATCH: "PASSWORDS_DO_NOT_MATCH",
  INVALID_NOTE_ID: "INVALID_NOTE_ID",

  // Resource errors
  NOT_FOUND: "NOT_FOUND",
  NOTE_NOT_FOUND: "NOTE_NOT_FOUND",
  USER_NOT_FOUND: "USER_NOT_FOUND",

  // Authorization errors
  FORBIDDEN: "FORBIDDEN",
  UNAUTHORIZED: "UNAUTHORIZED",

  // Conflict errors
  CONFLICT: "CONFLICT",
  EMAIL_EXISTS: "EMAIL_EXISTS",

  // Server errors
  INTERNAL_ERROR: "INTERNAL_ERROR",
  DATABASE_ERROR: "DATABASE_ERROR",
  SECURE_STORAGE_ERROR: "SECURE_STORAGE_ERROR",
  AUTH_UNAVAILABLE: "AUTH_UNAVAILABLE",

  // Network errors
  NETWORK_ERROR: "NETWORK_ERROR",
  TIMEOUT: "TIMEOUT",

  // Configuration errors
  INVALID_CONFIG: "INVALID_CONFIG",
  MISSING_CONFIG: "MISSING_CONFIG",
} as const;

/**
 * Type for error code values
 */
export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Structured error response from the backend
 */
export interface ErrorResponse {
  code: ErrorCodeValue;
  message: string;
  details?: string;
}

/**
 * Parse an error from Tauri command response
 *
 * @param error - The error object from Tauri command
 * @returns Parsed error response or null if parsing fails
 */
export function parseError(error: unknown): ErrorResponse | null {
  try {
    if (typeof error === "string") {
      return parseErrorString(error as string);
    } else if (error instanceof Error) {
      return parseErrorString(error.message);
    } else if (error && typeof error === "object" && "code" in error) {
      // Already structured error
      return error as ErrorResponse;
    }
  } catch {
    // If parsing fails, return null to indicate we couldn't parse it
    return null;
  }
  // If none of the conditions matched, return null
  return null;
}

/**
 * Parse an error string that might be JSON or a plain message
 *
 * @param errorString - The error string to parse
 * @returns Parsed error response or null if parsing fails
 */
function parseErrorString(errorString: string): ErrorResponse | null {
  try {
    // Try to parse as JSON first
    const parsed = JSON.parse(errorString);
    if (parsed && typeof parsed === "object" && "code" in parsed) {
      return {
        code: parsed.code as ErrorCodeValue,
        message: parsed.message as string,
        details: (parsed.details as string | undefined) ?? undefined,
      };
    }
    // If parsed but doesn't have code, treat as plain message
    return {
      code: ErrorCode.INTERNAL_ERROR,
      message: errorString,
    };
  } catch {
    // Not JSON, treat as plain message with unknown code
    return {
      code: ErrorCode.INTERNAL_ERROR,
      message: errorString,
    };
  }
}

/**
 * Check if an error is an authentication error
 *
 * @param error - The error to check
 * @returns True if the error is an authentication error
 */
export function isAuthError(error: ErrorResponse | string | unknown): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return isAuthErrorCode(parsed.code);
}

/**
 * Check if an error is a rate limit error
 *
 * @param error - The error to check
 * @returns True if the error is a rate limit error
 */
export function isRateLimitError(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return isRateLimitErrorCode(parsed.code);
}

/**
 * Check if an error is retryable
 *
 * @param error - The error to check
 * @returns True if the error is retryable
 */
export function isRetryableError(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return isRetryableErrorCode(parsed.code);
}

/**
 * Check if an error is a validation error
 *
 * @param error - The error to check
 * @returns True if the error is a validation error
 */
export function isValidationError(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return isValidationErrorCode(parsed.code);
}

/**
 * Check if an error is a not found error
 *
 * @param error - The error to check
 * @returns True if the error is a not found error
 */
export function isNotFoundError(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return isNotFoundErrorCode(parsed.code);
}

/**
 * Check if an error is an internal server error
 *
 * @param error - The error to check
 * @returns True if the error is an internal server error
 */
export function isInternalError(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return isInternalErrorCode(parsed.code);
}

/**
 * Check if an error requires authentication
 *
 * @param error - The error to check
 * @returns True if authentication is required
 */
export function isAuthRequired(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return parsed.code === ErrorCode.AUTH_REQUIRED;
}

/**
 * Check if an error indicates invalid credentials
 *
 * @param error - The error to check
 * @returns True if credentials are invalid
 */
export function isInvalidCredentials(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return parsed.code === ErrorCode.INVALID_CREDENTIALS;
}

/**
 * Check if an error indicates a note not found
 *
 * @param error - The error to check
 * @returns True if note was not found
 */
export function isNoteNotFound(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return parsed.code === ErrorCode.NOTE_NOT_FOUND;
}

/**
 * Check if an error indicates an invalid note ID
 *
 * @param error - The error to check
 * @returns True if note ID is invalid
 */
export function isInvalidNoteId(
  error: ErrorResponse | string | unknown,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;

  return parsed.code === ErrorCode.INVALID_NOTE_ID;
}

/**
 * Get user-friendly error message from an error
 *
 * @param error - The error to get message from
 * @returns User-friendly error message
 */
export function getErrorMessage(
  error: ErrorResponse | string | unknown,
): string {
  const parsed = parseError(error);
  if (!parsed) {
    return typeof error === "string" ? error : "An unknown error occurred";
  }
  return parsed.message;
}

/**
 * Get error code from an error
 *
 * @param error - The error to get code from
 * @returns Error code or null if parsing fails
 */
export function getErrorCode(
  error: ErrorResponse | string | unknown,
): ErrorCodeValue | null {
  const parsed = parseError(error);
  if (!parsed) return null;
  return parsed.code;
}

/**
 * Check if an error matches a specific error code
 *
 * @param error - The error to check
 * @param code - The error code to match against
 * @returns True if the error matches the code
 */
export function hasErrorCode(
  error: ErrorResponse | string | unknown,
  code: ErrorCodeValue,
): boolean {
  const parsed = parseError(error);
  if (!parsed) return false;
  return parsed.code === code;
}

/**
 * Get a user-friendly message for an error code
 *
 * @param code - The error code
 * @returns User-friendly message for the error code
 */
export function getErrorMessageForCode(code: ErrorCodeValue): string {
  const messages: Record<ErrorCodeValue, string> = {
    // Authentication errors
    [ErrorCode.AUTH_REQUIRED]: "Authentication required",
    [ErrorCode.INVALID_CREDENTIALS]: "Invalid credentials",
    [ErrorCode.TOKEN_EXPIRED]: "Your session has expired. Please log in again.",
    [ErrorCode.INVALID_TOKEN]: "Invalid authentication token",

    // Rate limiting errors
    [ErrorCode.RATE_LIMITED]: "Too many attempts. Please try again later.",
    [ErrorCode.DEVICE_RATE_LIMITED]:
      "Too many attempts from this device. Please try again later.",
    [ErrorCode.GLOBAL_RATE_LIMITED]:
      "Too many requests. Please try again later.",

    // Validation errors
    [ErrorCode.VALIDATION_ERROR]: "Invalid input",
    [ErrorCode.INVALID_EMAIL]: "Invalid email format",
    [ErrorCode.INVALID_PASSWORD]: "Invalid password format",
    [ErrorCode.PASSWORDS_DO_NOT_MATCH]: "Passwords do not match",
    [ErrorCode.INVALID_NOTE_ID]: "Invalid note ID",

    // Resource errors
    [ErrorCode.NOT_FOUND]: "Resource not found",
    [ErrorCode.NOTE_NOT_FOUND]: "Note not found",
    [ErrorCode.USER_NOT_FOUND]: "User not found",

    // Authorization errors
    [ErrorCode.FORBIDDEN]: "Access forbidden",
    [ErrorCode.UNAUTHORIZED]: "Unauthorized access",

    // Conflict errors
    [ErrorCode.CONFLICT]: "Resource conflict",
    [ErrorCode.EMAIL_EXISTS]: "Email already registered",

    // Server errors
    [ErrorCode.INTERNAL_ERROR]: "Internal server error",
    [ErrorCode.DATABASE_ERROR]: "Database error",
    [ErrorCode.SECURE_STORAGE_ERROR]: "Failed to access secure storage",
    [ErrorCode.AUTH_UNAVAILABLE]: "Authentication service unavailable",

    // Network errors
    [ErrorCode.NETWORK_ERROR]: "Network error",
    [ErrorCode.TIMEOUT]: "Request timeout",

    // Configuration errors
    [ErrorCode.INVALID_CONFIG]: "Invalid configuration",
    [ErrorCode.MISSING_CONFIG]: "Missing required configuration",
  };

  return messages[code] || "An error occurred";
}

/**
 * Check if an error code is an authentication error
 */
function isAuthErrorCode(code: ErrorCodeValue): boolean {
  return (
    code === ErrorCode.AUTH_REQUIRED ||
    code === ErrorCode.INVALID_CREDENTIALS ||
    code === ErrorCode.TOKEN_EXPIRED ||
    code === ErrorCode.INVALID_TOKEN
  );
}

/**
 * Check if an error code is a rate limit error
 */
function isRateLimitErrorCode(code: ErrorCodeValue): boolean {
  return (
    code === ErrorCode.RATE_LIMITED ||
    code === ErrorCode.DEVICE_RATE_LIMITED ||
    code === ErrorCode.GLOBAL_RATE_LIMITED
  );
}

/**
 * Check if an error code is retryable
 */
function isRetryableErrorCode(code: ErrorCodeValue): boolean {
  return (
    code === ErrorCode.RATE_LIMITED ||
    code === ErrorCode.DEVICE_RATE_LIMITED ||
    code === ErrorCode.GLOBAL_RATE_LIMITED ||
    code === ErrorCode.NETWORK_ERROR ||
    code === ErrorCode.TIMEOUT ||
    code === ErrorCode.INTERNAL_ERROR ||
    code === ErrorCode.DATABASE_ERROR
  );
}

/**
 * Check if an error code is a validation error
 */
function isValidationErrorCode(code: ErrorCodeValue): boolean {
  return (
    code === ErrorCode.VALIDATION_ERROR ||
    code === ErrorCode.INVALID_EMAIL ||
    code === ErrorCode.INVALID_PASSWORD ||
    code === ErrorCode.INVALID_NOTE_ID
  );
}

/**
 * Check if an error code is a not found error
 */
function isNotFoundErrorCode(code: ErrorCodeValue): boolean {
  return (
    code === ErrorCode.NOT_FOUND ||
    code === ErrorCode.NOTE_NOT_FOUND ||
    code === ErrorCode.USER_NOT_FOUND
  );
}

/**
 * Check if an error code is an internal server error
 */
function isInternalErrorCode(code: ErrorCodeValue): boolean {
  return (
    code === ErrorCode.INTERNAL_ERROR ||
    code === ErrorCode.DATABASE_ERROR ||
    code === ErrorCode.SECURE_STORAGE_ERROR ||
    code === ErrorCode.AUTH_UNAVAILABLE
  );
}
