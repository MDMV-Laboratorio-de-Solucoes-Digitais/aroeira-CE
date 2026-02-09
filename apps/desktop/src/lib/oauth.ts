import { goto } from "$app/navigation";
import { resolve } from "$app/paths";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { logAuditEvent, setSessionId } from "./audit";
import { handleError } from "./logger";

export type OAuthProvider = "google" | "github";

export interface OAuthAvailability {
  google: boolean;
  github: boolean;
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

export async function handleOAuthCallback(
  callbackUrl: string,
): Promise<OAuthUser> {
  return invoke<OAuthUser>("handle_oauth_callback", { callbackUrl });
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
  const allowedHosts =
    provider === "google"
      ? new Set([
          "accounts.google.com",
          "oauth2.googleapis.com",
          "www.googleapis.com",
        ])
      : new Set(["github.com"]);

  if (!allowedHosts.has(host)) {
    throw new Error(`Blocked untrusted ${provider} authorization host`);
  }

  try {
    await openUrl(parsed.toString());
  } catch (e) {
    console.error(`Failed to open ${provider} auth URL`, e);
    throw new Error(`Failed to open browser for ${provider} authentication`);
  }
}

// Serialize OAuth callback handling to avoid races without dropping events
let oauthCallbackQueue: Promise<void> = Promise.resolve();

export type OAuthStateCallbacks = {
  setLoading(_provider: OAuthProvider | null): void;
  setError(_msg: string): void;
  resetState(_msg?: string): void;
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

  const CALLBACK_SCHEME = "com.aroeira.app";
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

  const DEV_PORT = 1420;

  const isLocalhostDev =
    import.meta.env.DEV &&
    parsed.protocol === "http:" &&
    parsed.hostname === "localhost" &&
    parsed.port === String(DEV_PORT) &&
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
      const callbackForBackend =
        isLocalhostDev || isHostlessCallback
          ? `${CALLBACK_SCHEME}://${CALLBACK_HOST}${CALLBACK_PATH}${parsed.search}`
          : rawUrl;

      try {
        const user = await handleOAuthCallback(callbackForBackend);
        console.log("OAuth callback successful, user:", {
          provider: user.provider,
          email: redactEmail(user.email),
        });
        logAuditEvent("oauth_login", true, {
          provider: user.provider,
          email: redactEmail(user.email),
        });
        setSessionId();

        // Consume pending markers only after a successful exchange.
        localStorage.removeItem("oauth_pending_provider");
        localStorage.removeItem("oauth_pending_state");
        localStorage.removeItem("oauth_pending_started_at");

        // Clean up OAuth state on success
        callbacks.resetState();
        await goto(resolve("/dashboard"), { replaceState: true });
      } catch (err: unknown) {
        console.error("OAuth callback failed:", sanitizeErrorForAudit(err));
        logAuditEvent("oauth_login", false, {
          error: sanitizeErrorForAudit(err),
        });
        callbacks.setError(handleError(err, "OAuth authentication"));
      } finally {
        callbacks.resetState();
      }
    });

  return oauthCallbackQueue;
}
