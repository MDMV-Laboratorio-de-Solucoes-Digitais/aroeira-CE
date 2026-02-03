/**
 * OAuth utility module for handling OAuth2 authentication flows.
 *
 * This module provides functions to initiate OAuth flows with Google and GitHub,
 * opening the system browser for authentication and handling callbacks.
 */

import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

export type OAuthProvider = "google" | "github";

export interface StartOAuthResponse {
  auth_url: string;
  state: string;
}

export interface OAuthCallbackResponse {
  provider: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
}

/**
 * Starts an OAuth authentication flow for the given provider.
 *
 * This function:
 * 1. Calls the Tauri backend to generate an authorization URL
 * 2. Opens the URL in the system default browser
 * 3. Returns the state parameter for callback verification
 *
 * The actual callback handling happens via deep linking - the OS will
 * open the app with the aroeira://auth/callback URL when the provider
 * redirects back.
 *
 * @param provider - Either "google" or "github"
 * @returns The state parameter used for this flow
 * @throws Error if the provider is not configured or the flow fails
 */
export async function startOAuthFlow(provider: OAuthProvider): Promise<string> {
  const response = await invoke<StartOAuthResponse>("start_oauth_flow", {
    provider,
  });

  // Open the authorization URL in the system browser
  await openUrl(response.auth_url);

  return response.state;
}

/**
 * Handles an OAuth callback URL from deep linking.
 *
 * This function should be called when the app receives a deep link
 * with the aroeira://auth/callback URL.
 *
 * @param callbackUrl - The full callback URL from the deep link
 * @returns The authenticated user information
 * @throws Error if the callback is invalid or the exchange fails
 */
export async function handleOAuthCallback(
  callbackUrl: string,
): Promise<OAuthCallbackResponse> {
  let u: URL;
  try {
    u = new URL(callbackUrl);
  } catch {
    throw new Error("Invalid OAuth callback URL");
  }

  const schemeOk = u.protocol.toLowerCase() === "aroeira:";
  const canonicalOk =
    u.hostname === "auth" &&
    (u.pathname === "/callback" || u.pathname === "/callback/");
  const hostlessOk =
    u.hostname === "" &&
    (u.pathname === "/auth/callback" || u.pathname === "/auth/callback/");

  if (!schemeOk || (!canonicalOk && !hostlessOk)) {
    throw new Error("Invalid OAuth callback URL");
  }

  return invoke<OAuthCallbackResponse>("handle_oauth_callback", {
    callback_url: callbackUrl,
  });
}

/**
 * Checks if OAuth providers are available.
 *
 * This is a simple check to determine if we should show OAuth buttons.
 * In production, you might want to check with the backend which providers
 * are configured.
 *
 * @returns True if at least one OAuth provider might be available
 */
export function isOAuthAvailable(): boolean {
  // OAuth is always potentially available - the backend will return
  // an error if a specific provider is not configured
  return true;
}
