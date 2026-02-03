/**
 * Secure Logging Utility
 *
 * This utility provides secure, structured logging that avoids exposing sensitive data
 * such as PII, PHI, cardholder data, JWT tokens, passwords, or internal error details.
 *
 * All error messages are sanitized and generic, using error codes instead of raw messages.
 *
 * Uses the centralized error codes from error-handler.ts for consistency.
 */

import {
  getErrorCode,
  getErrorMessageForCode,
  type ErrorCodeValue,
} from "./error-handler";

// Re-export ErrorCode for consumers that import from logger
export { ErrorCode, type ErrorCodeValue } from "./error-handler";

/**
 * Log levels for structured logging
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

export const LogLevels = {
  DEBUG: "debug" as LogLevel,
  INFO: "info" as LogLevel,
  WARN: "warn" as LogLevel,
  ERROR: "error" as LogLevel,
} as const;

/**
 * Structured log entry interface
 */
interface LogEntry {
  timestamp: string;
  level: LogLevel;
  operation: string;
  success: boolean;
  errorCode?: ErrorCodeValue | null;
  errorType?: string;
  details?: Record<string, unknown>;
}

/**
 * Extracts error type (error name) from error object
 */
function extractErrorType(error: unknown): string {
  if (error instanceof Error) {
    return error.name;
  }
  return "Unknown";
}

/**
 * Writes a structured log entry to the console
 * Uses appropriate console method based on log level
 */
function writeLog(entry: LogEntry): void {
  const logEntry = JSON.stringify(entry);

  switch (entry.level) {
    case LogLevels.ERROR:
      console.error(logEntry);
      break;
    case LogLevels.WARN:
      console.warn(logEntry);
      break;
    case LogLevels.DEBUG:
      console.debug(logEntry);
      break;
    case LogLevels.INFO:
    default:
      console.log(logEntry);
      break;
  }
}

/**
 * Logs a successful operation
 * @param operation - The operation being performed
 * @param details - Optional additional details about the operation
 */
export function logSuccess(
  operation: string,
  details?: Record<string, unknown>,
): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level: LogLevels.INFO,
    operation,
    success: true,
    ...(details && { details }),
  };
  writeLog(entry);
}

/**
 * Logs an error operation with secure error handling
 * Never logs raw error messages - only error codes and types
 * @param operation - The operation that failed
 * @param error - The error object
 * @param details - Optional additional details about the error
 */
export function logError(
  operation: string,
  error: unknown,
  details?: Record<string, unknown>,
): void {
  const errorCode = getErrorCode(error);
  const errorType = extractErrorType(error);

  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level: LogLevels.ERROR,
    operation,
    success: false,
    errorCode,
    errorType,
    ...(details && { details }),
  };
  writeLog(entry);
}

/**
 * Logs a warning
 * @param operation - The operation being performed
 * @param message - Warning message (must be generic, no sensitive data)
 * @param details - Optional additional details
 */
export function logWarning(
  operation: string,
  message: string,
  details?: Record<string, unknown>,
): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level: LogLevels.WARN,
    operation,
    success: true,
    details: {
      message,
      ...details,
    },
  };
  writeLog(entry);
}

/**
 * Logs debug information
 * @param operation - The operation being performed
 * @param details - Debug details (must not contain sensitive data)
 */
export function logDebug(
  operation: string,
  details: Record<string, unknown>,
): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level: LogLevels.DEBUG,
    operation,
    success: true,
    details,
  };
  writeLog(entry);
}

/**
 * Generates a user-facing error message based on error code
 * These messages are safe to display to users
 * @param error - The error object
 * @param operation - The operation that failed
 * @returns A generic, user-friendly error message
 */
export function getUserErrorMessage(error: unknown, operation: string): string {
  const errorCode = getErrorCode(error);
  const baseMessage = errorCode
    ? getErrorMessageForCode(errorCode)
    : "An unknown error occurred";
  return `${operation.charAt(0).toUpperCase() + operation.slice(1)} failed. ${baseMessage}. Please try again.`;
}

/**
 * Handles errors consistently across the application
 * Logs the error securely and returns a user-friendly message
 * @param error - The error object
 * @param operation - The operation that failed
 * @param details - Optional additional details for logging
 * @returns A user-friendly error message
 */
export function handleError(
  error: unknown,
  operation: string,
  details?: Record<string, unknown>,
): string {
  logError(operation, error, details);
  return getUserErrorMessage(error, operation);
}
