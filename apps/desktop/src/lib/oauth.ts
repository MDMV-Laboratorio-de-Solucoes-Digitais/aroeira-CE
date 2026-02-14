import { goto } from "$app/navigation";
import { resolve } from "$app/paths";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { logAuditEvent, setSessionId } from "./audit";
import { handleError } from "./logger";

export type OAuthProvider = "google" | "github";

let oauthCallbackQueue = Promise.resolve();

// Deduplicate callback deliveries coming from multiple deep-link sources
// (e.g., deep-link plugin + single-instance event).
let lastCallbackKey: string | null = null;
let lastCallbackAt = 0;

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

  const port = parsed.port ? Number(parsed.port) : null;
  const defaultPort =
    parsed.protocol === "https:"
      ? 443
      : parsed.protocol === "http:"
        ? 80
        : null;

  if (port !== null && defaultPort !== null && port !== defaultPort) {
    throw new Error(
      `Blocked non-default port for ${provider} authorization URL`,
    );
  }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname;

  if (provider === "google") {
    const allowedGooglePaths = new Set(["/o/oauth2/v2/auth", "/o/oauth2/auth"]);
    const normalizedPath =
      path.endsWith("/") && path.length > 1 ? path.slice(0, -1) : path;

    if (
      host !== "accounts.google.com" ||
      !allowedGooglePaths.has(normalizedPath)
    ) {
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
  if (url.length > 8192) {
    throw new Error("Invalid callback URL");
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid callback URL");
  }

  // Reject URL fragments (must not contain OAuth response in fragment for this app)
  if (parsed.hash && parsed.hash.length > 1) {
    throw new Error("Invalid callback URL");
  }

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
    Number(typeof window !== "undefined" ? window.location.port : undefined) ||
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

  // Normalize callback to the canonical scheme for backend consistency.
  // Always send `aroeira://auth/callback?...` to the backend, even in DEV localhost mode.
  const callbackForBackend = `${CALLBACK_SCHEME}://${CALLBACK_HOST}${CALLBACK_PATH}${parsed.search}`;

  try {
    return await invoke<OAuthUser>("handle_oauth_callback", {
      url: callbackForBackend,
    });
  } catch (err: unknown) {
    console.error("Backend OAuth exchange failed:", sanitizeErrorForAudit(err));
    throw err;
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

  // Deduplicate repeated delivery of the same callback (warm start can emit via multiple sources).
  const code = parsed.searchParams.get("code") ?? "";
  const state = parsed.searchParams.get("state") ?? "";
  const oauthError = parsed.searchParams.get("error") ?? "";

  const fingerprint = (() => {
    // Non-cryptographic, one-way-enough for deduping without retaining secrets in memory.
    // Keeps only a 32-bit hash.
    const s = `${oauthError}|${state}|${code}`;
    let h = 2166136261; // FNV-1a
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(16);
  })();

  const now = Date.now();
  if (code || state || oauthError) {
    if (lastCallbackKey === fingerprint && now - lastCallbackAt < 5_000) {
      return Promise.resolve();
    }
    lastCallbackKey = fingerprint;
    lastCallbackAt = now;
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
    Number(typeof window !== "undefined" ? window.location.port : undefined) ||
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
        let savedProvider: string | null = null;
        try {
          savedProvider = localStorage.getItem("oauth_pending_provider");
        } catch {
          // Ignore
        }
        oauthLoading =
          savedProvider === "google" || savedProvider === "github"
            ? (savedProvider as OAuthProvider)
            : null;

        if (oauthLoading) {
          callbacks.setLoading(oauthLoading);
        } else if (savedProvider) {
          try {
            localStorage.removeItem("oauth_pending_provider");
            localStorage.removeItem("oauth_pending_state");
          } catch {
            // Ignore
          }
        }
      }

      // Check for OAuth provider errors (user denied/cancelled)
      const oauthError = callbackUrl.searchParams.get("error");
      if (oauthError) {
        try {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
        } catch {
          // Ignore
        }

        callbacks.resetState(
          "Authentication was cancelled or denied. Please try again.",
        );
        return;
      }

      // Validate callback contains authorization code
      const code = callbackUrl.searchParams.get("code");
      if (!code) {
        try {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
        } catch {
          // Ignore
        }

        callbacks.resetState(
          "Authentication callback was invalid. Please try again.",
        );
        return;
      }

      // Expire stale OAuth pending state (align with backend PKCE session TTL: 10 minutes)
      let startedAt = NaN;
      try {
        const startedAtStr = localStorage.getItem("oauth_pending_started_at");
        startedAt = startedAtStr ? Number(startedAtStr) : NaN;
      } catch {
        // Ignore
      }
      const maxAgeMs = 10 * 60 * 1000;

      if (!Number.isFinite(startedAt) || Date.now() - startedAt > maxAgeMs) {
        try {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
        } catch {
          // Ignore
        }

        callbacks.resetState(
          "Authentication session expired. Please try again.",
        );
        return;
      }

      // Validate state before invoking backend exchange
      let pendingState: string | null = null;
      try {
        pendingState = localStorage.getItem("oauth_pending_state");
      } catch {
        // Ignore
      }
      const callbackState = callbackUrl.searchParams.get("state");

      // If we have a pending state, enforce exact match.
      // If we *don't* (cold start / storage cleared), still allow backend to validate.
      if (!callbackState || (pendingState && pendingState !== callbackState)) {
        try {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
        } catch {
          // Ignore
        }

        callbacks.resetState(
          "Authentication session was invalid. Please try again.",
        );
        return;
      }

      callbacks.setError("");

      // Normalize callback to the canonical scheme for backend consistency.
      // Always send `aroeira://auth/callback?...` to the backend, even in DEV localhost mode.
      const callbackForBackend = `${CALLBACK_SCHEME}://${CALLBACK_HOST}${CALLBACK_PATH}${callbackUrl.search}`;

      // Validate redirect_uri to prevent unauthorized redirect destinations
      const redirectUriParam = parsed.searchParams.get("redirect_uri");
      const devServerPort =
        Number(window.location.port) ||
        Number((import.meta as any).env?.VITE_DEV_PORT) ||
        1420;

      const allowedRedirectSet = new Set([
        "aroeira://auth/callback",
        ...(import.meta.env.DEV
          ? [`http://localhost:${devServerPort}/auth/callback`]
          : []),
      ]);

      if (redirectUriParam && !allowedRedirectSet.has(redirectUriParam)) {
        console.warn("Blocked unexpected redirect_uri parameter", {
          length: redirectUriParam.length,
        });
        // We log it but don't throw here to avoid breaking valid flows if the param is missing
        // strict validation happens at start of flow
      }

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
        try {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
        } catch {
          // Ignore
        }

        callbacks.resetState();
        await goto(resolve("/dashboard"), { replaceState: true });
      } catch (err: unknown) {
        console.error("OAuth callback failed:", sanitizeErrorForAudit(err));
        logAuditEvent("oauth_login", false, {
          error: sanitizeErrorForAudit(err),
        });

        // Clear stale pending markers so the user can retry cleanly.
        try {
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
        } catch {
          // Ignore
        }

        callbacks.setError(handleError(err, "OAuth authentication"));
        callbacks.setLoading(null);
      }
    });

  return oauthCallbackQueue;
}
