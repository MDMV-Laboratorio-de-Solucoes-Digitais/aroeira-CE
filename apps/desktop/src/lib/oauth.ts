/**
 * OAuth utility module for handling OAuth2 authentication flows.
 *
 * This module provides functions to initiate OAuth flows with Google and GitHub,
 * opening system browser for authentication and handling callbacks.
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

export interface OAuthAvailability {
  google: boolean;
  github: boolean;
}

/**
 * Starts an OAuth authentication flow for given provider.
 *
 * This function:
 * 1. Calls Tauri backend to generate an authorization URL
 * 2. Opens URL in system default browser
 * 3. Returns state parameter for callback verification
 *
 * The actual callback handling happens via deep linking - OS will
 * open app with aroeira://auth/callback URL when provider
 * redirects back.
 *
 * @param provider - Either "google" or "github"
 * @returns The state parameter used for this flow
 * @throws Error if provider is not configured or flow fails
 */
export async function startOAuthFlow(provider: OAuthProvider): Promise<string> {
  const response = await invoke<StartOAuthResponse>("start_oauth_flow", {
    provider,
  });

  const url = new URL(response.auth_url);
  if (url.protocol !== "https:") {
    throw new Error("Invalid authorization URL");
  }

  const allowedHostnames =
    provider === "google"
      ? new Set(["accounts.google.com"])
      : new Set(["github.com"]);

  if (!allowedHostnames.has(url.hostname)) {
    throw new Error("Unexpected authorization host");
  }

  await openUrl(url.toString());

  return response.state;
}

/**
 * Handles an OAuth callback URL from deep linking.
 *
 * This function should be called when the app receives a deep link
 * with aroeira://auth/callback URL.
 *
 * @param callbackUrl - The full callback URL from deep link
 * @returns The authenticated user information
 * @throws Error if callback is invalid or exchange fails
 */
export async function handleOAuthCallback(
  callbackUrl: string,
): Promise<OAuthCallbackResponse> {
  return invoke<OAuthCallbackResponse>("handle_oauth_callback", {
    callbackUrl: callbackUrl,
  });
}

/**
 * Checks which OAuth providers are available by querying the backend.
 *
 * This provides a better user experience by only showing OAuth buttons
 * for providers that are actually configured on the server.
 *
 * @returns Availability status for each provider
 * @throws Error if backend query fails
 */
export async function getOAuthAvailability(): Promise<OAuthAvailability> {
  return invoke<OAuthAvailability>("get_oauth_availability");
}

/**
 * Checks if any OAuth provider is available.
 *
 * This is a simple check to determine if we should show OAuth section.
 * Uses the availability check to provide accurate information.
 *
 * @returns True if at least one OAuth provider might be available
 */
export async function isOAuthAvailable(): Promise<boolean> {
  const availability = await getOAuthAvailability();
  return availability.google || availability.github;
}
