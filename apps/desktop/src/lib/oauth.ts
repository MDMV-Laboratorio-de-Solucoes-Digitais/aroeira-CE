import { goto } from "$app/navigation";
import { resolve } from "$app/paths";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { logAuditEvent, setSessionId } from "./audit";
import { handleError } from "./logger";

export type OAuthProvider = "google" | "github";

let oauthCallbackQueue = Promise.resolve();

export interface OAuthStateCallbacks {
  setLoading: (_provider: OAuthProvider | null) => void;
  setError: (_error: string) => void;
  resetState: (_msg?: string) => void;
}

export interface OAuthUser {
  provider: string;
  email: string;
  name?: string;
  avatar_url?: string;
}

export interface StartOAuthResponse {
  auth_url: string;
  state: string;
}

export interface OAuthAvailability {
  google: boolean;
  github: boolean;
}

// Helper function to redact email addresses for audit logging
function redactEmail(email: string): string {
  const [, domain] = email.split("@");
  if (!domain) return "***@***";
  return `***@${domain}`;
}

// Helper function to sanitize error messages for audit logging
export function sanitizeErrorForAudit(err: unknown): string {
  const errorStr = String(err);
  if (
    errorStr.includes("callback") ||
    errorStr.includes("com.aroeira.app") ||
    errorStr.includes("aroeira://")
  ) {
    return "callback_processing_error";
  }
  if (errorStr.includes("token") || errorStr.includes("exchange")) {
    return "token_exchange_error";
  }
  if (errorStr.includes("network") || errorStr.includes("fetch")) {
    return "network_error";
  }
  if (errorStr.includes("expired") || errorStr.includes("invalid")) {
    return "session_invalid_or_expired";
  }
  if (errorStr.includes("denied") || errorStr.includes("cancelled")) {
    return "user_denied_or_cancelled";
  }
  return "authentication_error";
}

export async function getOAuthAvailability(): Promise<OAuthAvailability> {
  return invoke<OAuthAvailability>("get_oauth_availability");
}

export async function startOAuthFlow(
  provider: OAuthProvider,
): Promise<StartOAuthResponse> {
  return invoke<StartOAuthResponse>("start_oauth_flow", { provider });
}

export async function openOAuthAuthUrl(
  provider: OAuthProvider,
  url: string,
): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid ${provider} authorization URL`);
  }

  // Prevent open-redirect / phishing via arbitrary URLs
  if (parsed.protocol !== "https:") {
    throw new Error(`Blocked non-HTTPS ${provider} authorization URL`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`Blocked credentialed ${provider} authorization URL`);
  }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname;

  if (provider === "google") {
    if (host !== "accounts.google.com" || path !== "/o/oauth2/v2/auth") {
      throw new Error("Blocked untrusted Google authorization endpoint");
    }
  } else {
    if (host !== "github.com" || path !== "/login/oauth/authorize") {
      throw new Error("Blocked untrusted GitHub authorization endpoint");
    }
  }

  try {
    await openUrl(parsed.toString());
  } catch (e) {
    console.error(`Failed to open ${provider} auth URL`, e);
    throw new Error(`Failed to open browser for ${provider} authentication`);
  }
}

/**
 * Handle the OAuth callback
 * This is called when the app is opened via deep link
 */
export const handleOAuthCallback = async (url: string): Promise<OAuthUser> => {
  const parsed = new URL(url);
  const rawUrl = url;

  // Constants
  const CALLBACK_SCHEME = "aroeira";
  const CALLBACK_HOST = "auth";
  const CALLBACK_PATH = "/callback";
  const HOSTLESS_PATH = "auth/callback";

  const isCanonicalCallback =
    parsed.protocol === `${CALLBACK_SCHEME}:` &&
    parsed.hostname === CALLBACK_HOST &&
    parsed.pathname === CALLBACK_PATH;

  const isHostlessCallback =
    parsed.protocol === `${CALLBACK_SCHEME}:` &&
    parsed.hostname === "" &&
    parsed.pathname.replace(/^\/+/, "") === HOSTLESS_PATH;

  const devPort =
    Number(window.location.port) ||
    Number((import.meta as any).env?.VITE_DEV_PORT) ||
    1420;

  const isLocalhostDev =
    import.meta.env.DEV &&
    parsed.protocol === "http:" &&
    parsed.hostname === "localhost" &&
    parsed.port === String(devPort) &&
    parsed.pathname === "/auth/callback";

  const isOAuthCallback =
    isCanonicalCallback || isHostlessCallback || isLocalhostDev;

  if (!isOAuthCallback) {
    // Not an OAuth callback we recognize
    throw new Error("Invalid callback URL");
  }

  // Normalize callback to the canonical scheme for backend consistency
  // This ensures the backend (which expects com.aroeira.app://auth/callback)
  // always receives a consistent URL format regardless of how the OS invoked the app.
  const callbackForBackend = isHostlessCallback
    ? `${CALLBACK_SCHEME}://${CALLBACK_HOST}${CALLBACK_PATH}${parsed.search}`
    : rawUrl;

  try {
    return await invoke<OAuthUser>("handle_oauth_callback", {
      url: callbackForBackend,
    });
  } catch (err: unknown) {
    console.error("Backend OAuth exchange failed:", err);
    throw err; // Re-throw to be handled by caller
  }
};

/**
 * Process an OAuth callback URL from deep linking.
 * This handles the aroeira://auth/callback URLs.
 */
export function processOAuthCallback(
  rawUrl: string,
  callbacks: OAuthStateCallbacks,
  getLoadingState: () => OAuthProvider | null,
): Promise<void> {
  // Only emit minimal info; never include code/state/raw URL
  if (import.meta.env.DEV) {
    console.debug("Processing OAuth callback", { length: rawUrl.length });
  }
  // Defensive bound to avoid processing extremely large deep-link payloads
  if (rawUrl.length > 8192) {
    callbacks.resetState(
      "Authentication callback was invalid. Please try again.",
    );
    return Promise.resolve();
  }

  const CALLBACK_SCHEME = "aroeira";
  const CALLBACK_HOST = "auth";
  const CALLBACK_PATH = "/callback";
  const HOSTLESS_PATH = "auth/callback";

  let parsed: URL | null = null;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // If this looks like our scheme but isn't parseable, treat as a failed callback
    if (rawUrl.startsWith(`${CALLBACK_SCHEME}:`)) {
      callbacks.resetState(
        "Authentication callback was invalid. Please try again.",
      );
    }
    return Promise.resolve();
  }

  const isCanonicalCallback =
    parsed.protocol === `${CALLBACK_SCHEME}:` &&
    parsed.hostname === CALLBACK_HOST &&
    parsed.pathname === CALLBACK_PATH;

  // Handle hostless URLs (e.g., com.aroeira.app:auth/callback)
  // Some OS implementations might strip the // authority markers
  const isHostlessCallback =
    parsed.protocol === `${CALLBACK_SCHEME}:` &&
    parsed.hostname === "" &&
    parsed.pathname.replace(/^\/+/, "") === HOSTLESS_PATH;

  const devPort =
    Number(window.location.port) ||
    Number((import.meta as any).env?.VITE_DEV_PORT) ||
    1420;

  const isLocalhostDev =
    import.meta.env.DEV &&
    parsed.protocol === "http:" &&
    parsed.hostname === "localhost" &&
    parsed.port === String(devPort) &&
    parsed.pathname === "/auth/callback";

  const isOAuthCallback =
    isCanonicalCallback || isHostlessCallback || isLocalhostDev;

  if (!isOAuthCallback) {
    // Ignore unrelated deep links; don't cancel an in-progress OAuth flow.
    if (import.meta.env.DEV) {
      console.debug("Not an OAuth callback, ignoring");
    }
    return Promise.resolve();
  }

  const callbackUrl = parsed;

  oauthCallbackQueue = oauthCallbackQueue
    .catch(() => {
      // Keep the queue alive even if a previous callback failed
    })
    .then(async () => {
      // Restore loading state from localStorage if not already set
      let oauthLoading = getLoadingState();
      if (!oauthLoading) {
        const savedProvider = localStorage.getItem("oauth_pending_provider");
        oauthLoading =
          savedProvider === "google" || savedProvider === "github"
            ? (savedProvider as OAuthProvider)
            : null;

        if (oauthLoading) {
          callbacks.setLoading(oauthLoading);
        } else if (savedProvider) {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
        }
      }

      // Check for OAuth provider errors (user denied/cancelled)
      const oauthError = callbackUrl.searchParams.get("error");
      if (oauthError) {
        callbacks.resetState(
          "Authentication was cancelled or denied. Please try again.",
        );
        return;
      }

      // Validate callback contains authorization code
      const code = callbackUrl.searchParams.get("code");
      if (!code) {
        callbacks.resetState(
          "Authentication callback was invalid. Please try again.",
        );
        return;
      }

      // Expire stale OAuth pending state (> 2 minutes)
      const startedAtStr = localStorage.getItem("oauth_pending_started_at");
      const startedAt = startedAtStr ? Number(startedAtStr) : NaN;
      const maxAgeMs = 2 * 60 * 1000;

      if (!Number.isFinite(startedAt) || Date.now() - startedAt > maxAgeMs) {
        callbacks.resetState(
          "Authentication session expired. Please try again.",
        );
        return;
      }

      // Validate state before invoking backend exchange
      const pendingState = localStorage.getItem("oauth_pending_state");
      const callbackState = callbackUrl.searchParams.get("state");
      if (!pendingState || !callbackState || pendingState !== callbackState) {
        callbacks.resetState(
          "Authentication session was invalid. Please try again.",
        );
        return;
      }

      callbacks.setError("");

      // Normalize callback to the canonical scheme for backend consistency
      // This ensures the backend (which expects com.aroeira.app://auth/callback)
      // always receives a consistent URL format regardless of how the OS invoked the app.
      const callbackForBackend = isHostlessCallback
        ? `${CALLBACK_SCHEME}://${CALLBACK_HOST}${CALLBACK_PATH}${parsed.search}`
        : rawUrl;

      try {
        const user = await handleOAuthCallback(callbackForBackend);
        if (import.meta.env.DEV) {
          console.debug("OAuth callback successful", {
            provider: user.provider,
            email: redactEmail(user.email),
          });
        }
        logAuditEvent("oauth_login", true, {
          provider: user.provider,
          email: redactEmail(user.email),
        });
        setSessionId();

        // Consume pending markers only after a successful exchange.
        localStorage.removeItem("oauth_pending_provider");
        localStorage.removeItem("oauth_pending_state");
        localStorage.removeItem("oauth_pending_started_at");

        callbacks.resetState();
        await goto(resolve("/dashboard"), { replaceState: true });
      } catch (err: unknown) {
        console.error("OAuth callback failed:", sanitizeErrorForAudit(err));
        logAuditEvent("oauth_login", false, {
          error: sanitizeErrorForAudit(err),
        });

        // Clear stale pending markers so the user can retry cleanly.
        localStorage.removeItem("oauth_pending_provider");
        localStorage.removeItem("oauth_pending_state");
        localStorage.removeItem("oauth_pending_started_at");

        callbacks.setError(handleError(err, "OAuth authentication"));
        callbacks.setLoading(null);
      }
    });

  return oauthCallbackQueue;
}
