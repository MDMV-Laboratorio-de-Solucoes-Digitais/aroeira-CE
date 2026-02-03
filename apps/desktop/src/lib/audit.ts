// Audit logging utility with user identifier support
// Supports both authenticated user_id (from JWT) and anonymous session tracking

import { invoke } from "@tauri-apps/api/core";
import { logSuccess, logError } from "./logger";

let currentSessionId: string | null = null;
let currentUserId: string | null = null;

/**
 * Generates a secure random session ID
 * Uses crypto.randomUUID() if available, falls back to getRandomValues
 * Throws an error if no secure randomness source is available
 */
function generateSessionId(): string {
  const crypto = globalThis.crypto;

  if (crypto?.randomUUID) {
    return crypto.randomUUID().replace(/-/g, "");
  }

  if (crypto?.getRandomValues) {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      "",
    );
  }

  // Fail closed: no secure randomness available
  throw new Error("Secure randomness unavailable");
}

/**
 * Extracts user ID from the stored JWT token
 * Returns null if no valid token is available or if extraction fails
 * This function only uses user_id from verified JWT tokens for security
 */
async function extractUserIdFromToken(): Promise<string | null> {
  try {
    const userId = await invoke<string | null>("get_user_id_from_token");
    return userId;
  } catch (error) {
    // Log the error but don't throw - audit logging should not break the app
    logError(
      "audit:user_id_extraction",
      error instanceof Error ? error : new Error(String(error)),
      { reason: "Failed to extract user_id from JWT token" },
    );
    return null;
  }
}

/**
 * Sets current session ID and extracts user ID from JWT token (called on successful login)
 * This is stored in memory only, not persisted to localStorage for security
 * User ID is extracted from verified JWT token for compliance
 */
export async function setSessionId(): Promise<void> {
  try {
    currentSessionId = generateSessionId();
    // Extract user_id from the JWT token for audit compliance
    currentUserId = await extractUserIdFromToken();
  } catch (error) {
    // Avoid breaking post-login flow if secure randomness is unavailable.
    // Keep session anonymous rather than throwing, but log for observability.
    logError(
      "audit:session_id_generation",
      error instanceof Error ? error : new Error(String(error)),
      { reason: "Failed to generate secure session id" },
    );
    currentSessionId = null;
    currentUserId = null;
  }
}

/**
 * Refreshes the cached user ID from the JWT token
 * Use this when authentication state may have changed (e.g., after token refresh)
 * Returns true if user_id was successfully refreshed, false otherwise
 */
export async function refreshUserId(): Promise<boolean> {
  const userId = await extractUserIdFromToken();
  const normalized = userId?.trim() || null;
  currentUserId = normalized;
  return normalized !== null;
}

/**
 * Gets current user identifier
 * Priority order for audit compliance:
 * 1. Authenticated user_id from JWT token (when available)
 * 2. Session ID for anonymous tracking (when not authenticated)
 * 3. "anonymous" if neither is available
 *
 * This ensures audit logs can reconstruct user-attributed events for compliance
 */
export function getCurrentUserId(): string {
  // Use authenticated user_id when available for compliance
  if (currentUserId !== null) {
    return currentUserId;
  }
  // Fall back to session ID for anonymous actions
  if (currentSessionId !== null) {
    return currentSessionId;
  }
  // No session at all
  return "anonymous";
}

/**
 * Clears current session ID and user ID (called on logout)
 */
export function clearSessionId(): void {
  currentSessionId = null;
  currentUserId = null;
}

/**
 * Logs an audit event with user identifier
 * Uses secure logger to avoid exposing sensitive data
 * @param action - The action being performed (e.g., "login", "note_create")
 * @param success - Whether action was successful
 * @param details - Optional additional details about action (must not contain sensitive data)
 */
export function logAuditEvent(
  action: string,
  success: boolean,
  details?: Record<string, unknown>,
): void {
  // Redact sensitive keys from details to prevent data leakage
  const redactDetails = (
    d: Record<string, unknown>,
  ): Record<string, unknown> => {
    const redacted: Record<string, unknown> = {};
    const blocked = new Set([
      "password",
      "token",
      "access_token",
      "refresh_token",
      "authorization",
      "cookie",
      "secret",
    ]);

    for (const [key, value] of Object.entries(d)) {
      if (blocked.has(key.toLowerCase())) continue;
      redacted[key] = value;
    }
    return redacted;
  };

  const safeDetails = details ? redactDetails(details) : undefined;

  if (success) {
    logSuccess(`audit:${action}`, {
      userId: getCurrentUserId(),
      ...(safeDetails && { details: safeDetails }),
    });
  } else {
    logError(`audit:${action}`, new Error("Audit event failed"), {
      userId: getCurrentUserId(),
      ...(safeDetails && { details: safeDetails }),
    });
  }
}
