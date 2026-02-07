<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { logAuditEvent, setSessionId } from "$lib/audit";
  import { Button } from "$lib/components/ui/button";
  import * as Card from "$lib/components/ui/card";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { handleError } from "$lib/logger";
  import {
    getOAuthAvailability,
    handleOAuthCallback,
    openOAuthAuthUrl,
    startOAuthFlow,
    type OAuthAvailability,
    type OAuthProvider,
  } from "$lib/oauth";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
  import { Check, Circle, Loader2, Lock, ShieldCheck, X } from "lucide-svelte";
  import { onDestroy, onMount } from "svelte";
  import { fly } from "svelte/transition";

  // Helper function to redact email addresses for audit logging
  function redactEmail(email: string): string {
    const [, domain] = email.split("@");
    if (!domain) return "***@***";
    return `***@${domain}`;
  }

  // Helper function to sanitize error messages for audit logging
  // Removes potentially sensitive data like URLs, tokens, or OAuth parameters
  function sanitizeErrorForAudit(err: unknown): string {
    const errorStr = String(err);
    // Map specific errors to generic categories without leaking details
    if (errorStr.includes("callback") || errorStr.includes("aroeira://")) {
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
    // Generic fallback - never log raw error content
    return "authentication_error";
  }

  let isLogin = $state(true);
  let loading = $state(false);
  let oauthLoading = $state<OAuthProvider | null>(null);
  let oauthTimeout: ReturnType<typeof setTimeout> | null = null;
  let destroyed = false;
  let error = $state("");
  let successMessage = $state("");
  let email = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let isPasswordFocused = $state(false);
  let unlistenDeepLink: UnlistenFn | null = null;
  let unlistenDeepLinkEvent: UnlistenFn | null = null;

  type PasswordSecurityLevel =
    | "none"
    | "minimum"
    | "secure"
    | "strict"
    | "paranoid";
  interface PasswordPolicy {
    level: PasswordSecurityLevel;
    min_length: number;
  }

  let policy = $state<PasswordPolicy>({ level: "secure", min_length: 8 });
  let oauthAvailability = $state<OAuthAvailability | null>(null);

  // Serialize OAuth callback handling to avoid races without dropping events
  let oauthCallbackQueue: Promise<void> = Promise.resolve();

  /**
   * Process an OAuth callback URL from deep linking.
   * This handles the aroeira://auth/callback URLs.
   */
  function processOAuthCallback(rawUrl: string): Promise<void> {
    // Only emit minimal info; never include code/state/raw URL
    if (import.meta.env.DEV) {
      console.debug("Processing OAuth callback", { length: rawUrl.length });
    }
    // Defensive bound to avoid processing extremely large deep-link payloads
    if (rawUrl.length > 8192) {
      oauthLoading = null;
      localStorage.removeItem("oauth_pending_provider");
      localStorage.removeItem("oauth_pending_state");
      localStorage.removeItem("oauth_pending_started_at");
      error = "Authentication callback was invalid. Please try again.";
      if (oauthTimeout) clearTimeout(oauthTimeout);
      oauthTimeout = null;
      return Promise.resolve();
    }

    let parsed: URL | null = null;
    try {
      parsed = new URL(rawUrl);
    } catch {
      // If this looks like our scheme but isn't parseable, treat as a failed callback
      if (rawUrl.startsWith("aroeira:")) {
        oauthLoading = null;
        localStorage.removeItem("oauth_pending_provider");
        localStorage.removeItem("oauth_pending_state");
        error = "Authentication callback was invalid. Please try again.";
        if (oauthTimeout) clearTimeout(oauthTimeout);
        oauthTimeout = null;
      }
      return Promise.resolve();
    }

    const isAroeiraProtocol =
      parsed.protocol === "aroeira:" &&
      parsed.hostname === "auth" &&
      parsed.pathname === "/callback";

    const isLocalhostDev =
      import.meta.env.DEV &&
      parsed.protocol === "http:" &&
      parsed.hostname === "localhost" &&
      parsed.pathname === "/auth/callback";

    const isOAuthCallback = isAroeiraProtocol || isLocalhostDev;

    if (import.meta.env.DEV) {
      console.debug("Parsed URL", {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        pathname: parsed.pathname,
        isOAuthCallback,
      });
    }

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
        if (destroyed) return;

        // Restore loading state from localStorage if not already set
        if (!oauthLoading) {
          const savedProvider = localStorage.getItem("oauth_pending_provider");
          oauthLoading =
            savedProvider === "google" || savedProvider === "github"
              ? (savedProvider as OAuthProvider)
              : null;

          if (!oauthLoading && savedProvider) {
            localStorage.removeItem("oauth_pending_provider");
            localStorage.removeItem("oauth_pending_state");
          }
        }

        // Check for OAuth provider errors (user denied/cancelled)
        const oauthError = callbackUrl.searchParams.get("error");
        if (oauthError) {
          oauthLoading = null;
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          error = "Authentication was cancelled or denied. Please try again.";
          if (oauthTimeout) clearTimeout(oauthTimeout);
          oauthTimeout = null;
          return;
        }

        // Validate callback contains authorization code
        const code = callbackUrl.searchParams.get("code");
        const state = callbackUrl.searchParams.get("state");
        if (import.meta.env.DEV) {
          console.debug("OAuth callback params", {
            hasCode: !!code,
            hasState: !!state,
            codeLength: code?.length,
            stateLength: state?.length,
          });
        }
        if (!code) {
          oauthLoading = null;
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          error = "Authentication callback was invalid. Please try again.";
          if (oauthTimeout) clearTimeout(oauthTimeout);
          oauthTimeout = null;
          return;
        }

        // Expire stale OAuth pending state (> 2 minutes)
        const startedAtStr = localStorage.getItem("oauth_pending_started_at");
        const startedAt = startedAtStr ? Number(startedAtStr) : NaN;
        const maxAgeMs = 2 * 60 * 1000;

        if (!Number.isFinite(startedAt) || Date.now() - startedAt > maxAgeMs) {
          oauthLoading = null;
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          error = "Authentication session expired. Please try again.";
          if (oauthTimeout) clearTimeout(oauthTimeout);
          oauthTimeout = null;
          return;
        }

        // Validate state before invoking backend exchange
        const pendingState = localStorage.getItem("oauth_pending_state");
        const callbackState = callbackUrl.searchParams.get("state");
        if (import.meta.env.DEV) {
          console.debug("State validation", {
            hasPendingState: !!pendingState,
            hasCallbackState: !!callbackState,
            match: pendingState === callbackState,
          });
        }
        if (!pendingState || !callbackState || pendingState !== callbackState) {
          oauthLoading = null;
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          error = "Authentication session was invalid. Please try again.";
          if (oauthTimeout) clearTimeout(oauthTimeout);
          oauthTimeout = null;
          return;
        }

        error = "";

        try {
          if (import.meta.env.DEV) {
            console.debug("Calling handleOAuthCallback with backend");
          }
          const user = await handleOAuthCallback(rawUrl);
          console.log("OAuth callback successful, user:", {
            provider: user.provider,
            email: redactEmail(user.email),
          });
          logAuditEvent("oauth_login", true, {
            provider: user.provider,
            email: redactEmail(user.email),
          });
          setSessionId();
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          await goto(resolve("/dashboard"), { replaceState: true });
        } catch (err: unknown) {
          console.error("OAuth callback failed:", err);
          logAuditEvent("oauth_login", false, {
            error: sanitizeErrorForAudit(err),
          });
          error = handleError(err, "OAuth authentication");
        } finally {
          oauthLoading = null;
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          if (oauthTimeout) clearTimeout(oauthTimeout);
          oauthTimeout = null;
        }
      });

    return oauthCallbackQueue;
  }

  onMount(async () => {
    try {
      policy = await invoke("get_password_policy");
    } catch (err) {
      console.error(
        "Failed to fetch password policy",
        sanitizeErrorForAudit(err),
      );
    }

    // Check OAuth availability
    try {
      oauthAvailability = await getOAuthAvailability();
    } catch (err) {
      console.error(
        "Failed to check OAuth availability",
        sanitizeErrorForAudit(err),
      );
      oauthAvailability = null;
    }

    // Check if the app was opened via a deep link (cold start)
    try {
      const urls = await getCurrent();
      if (urls && urls.length > 0) {
        for (const url of urls) {
          await processOAuthCallback(url);
        }
      }
    } catch (err) {
      console.error(
        "Failed to check initial deep links",
        sanitizeErrorForAudit(err),
      );
    }

    // Listen for deep links while the app is running (warm start)
    try {
      unlistenDeepLink = await onOpenUrl(async (urls) => {
        console.log("Deep link received:", urls);
        for (const url of urls) {
          await processOAuthCallback(url);
        }
      });
      console.log("Deep link listener setup successfully");
    } catch (err) {
      console.error(
        "Failed to setup deep link listener",
        sanitizeErrorForAudit(err),
      );
    }

    // Listen for deep-link events from single-instance plugin
    try {
      unlistenDeepLinkEvent = await listen<string>(
        "deep-link",
        async (event) => {
          console.log("Deep link event received:", event.payload);
          await processOAuthCallback(event.payload);
        },
      );
      console.log("Deep link event listener setup successfully");
    } catch (err) {
      console.error(
        "Failed to setup deep link event listener",
        sanitizeErrorForAudit(err),
      );
    }
  });

  onDestroy(() => {
    destroyed = true;
    // Idempotent cleanup: capture and nullify reference before calling
    const unlisten = unlistenDeepLink;
    unlistenDeepLink = null;
    if (unlisten) {
      unlisten();
    }

    const unlistenEvent = unlistenDeepLinkEvent;
    unlistenDeepLinkEvent = null;
    if (unlistenEvent) {
      unlistenEvent();
    }

    if (oauthTimeout) {
      clearTimeout(oauthTimeout);
      oauthTimeout = null;
    }

    if (oauthLoading !== null) {
      oauthLoading = null;
      localStorage.removeItem("oauth_pending_provider");
      localStorage.removeItem("oauth_pending_state");
      localStorage.removeItem("oauth_pending_started_at");
    }
  });

  // Derived state for password rules - use Array.from to count Unicode code points correctly
  let hasMinLength = $derived([...password].length >= policy.min_length);
  // Optimization: Only check regex if level requires it
  let requiresComplexity = $derived(
    ["secure", "strict", "paranoid"].includes(policy.level),
  );

  // Use Unicode property escapes to match backend behavior exactly
  let hasUppercase = $derived(
    !requiresComplexity || /\p{Upper}/u.test(password),
  );
  let hasLowercase = $derived(
    !requiresComplexity || /\p{Lower}/u.test(password),
  );
  let hasNumber = $derived(!requiresComplexity || /\p{Number}/u.test(password));
  let hasSpecial = $derived(
    !requiresComplexity || /[^\p{Alphabetic}\p{Number}\s]/u.test(password),
  );

  let allRulesMet = $derived(
    hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSpecial,
  );

  async function handleSubmit(e: Event) {
    e.preventDefault();
    loading = true;
    error = "";

    try {
      if (isLogin) {
        await invoke("login", { email, password });
        setSessionId();
        logAuditEvent("login", true, { email: redactEmail(email) });
        await goto(resolve("/dashboard"), { replaceState: true });
      } else {
        if (password !== confirmPassword) {
          error = "Passwords do not match";
          return;
        }
        await invoke("register", { email, password, confirmPassword });
        logAuditEvent("register", true, { email: redactEmail(email) });
        isLogin = true;
        successMessage = "Registration successful! Please login.";
        error = ""; // Clear any existing error
        email = "";
        password = "";
        confirmPassword = "";
      }
    } catch (err: unknown) {
      logAuditEvent(isLogin ? "login" : "register", false, {
        email: redactEmail(email),
      });
      error = handleError(err, "authentication");
    } finally {
      loading = false;
    }
  }

  function dismissError() {
    error = "";
  }

  /**
   * Start an OAuth login flow with the specified provider.
   */
  async function handleOAuthLogin(provider: OAuthProvider): Promise<void> {
    if (oauthLoading) return; // Prevent multiple clicks

    if (!oauthAvailability || !oauthAvailability[provider]) {
      error = "This sign-in method is not available.";
      return;
    }

    oauthLoading = provider;
    error = "";

    // Save provider to localStorage for cold start recovery
    localStorage.setItem("oauth_pending_provider", provider);
    localStorage.setItem("oauth_pending_started_at", String(Date.now()));

    // Prevent the UI from getting stuck if the callback never arrives
    if (oauthTimeout) clearTimeout(oauthTimeout);
    oauthTimeout = setTimeout(
      () => {
        if (oauthLoading === provider) {
          oauthLoading = null;
          localStorage.removeItem("oauth_pending_provider");
          localStorage.removeItem("oauth_pending_state");
          localStorage.removeItem("oauth_pending_started_at");
          error = "Authentication timed out. Please try again.";
        }
        oauthTimeout = null;
      },
      2 * 60 * 1000,
    );

    try {
      const { auth_url, state } = await startOAuthFlow(provider);
      if (destroyed) return;
      localStorage.setItem("oauth_pending_state", state);
      await openOAuthAuthUrl(provider, auth_url);
      // The browser will open and redirect back via deep link
      // The callback is handled by processOAuthCallback
    } catch (err: unknown) {
      if (destroyed) return;
      logAuditEvent("oauth_start", false, {
        provider,
        error: sanitizeErrorForAudit(err),
      });
      error = handleError(err, `${provider} authentication`);
      oauthLoading = null;
      localStorage.removeItem("oauth_pending_provider");
      localStorage.removeItem("oauth_pending_state");
      localStorage.removeItem("oauth_pending_started_at");
      if (oauthTimeout) clearTimeout(oauthTimeout);
      oauthTimeout = null;
    }
  }
</script>

<div class="fixed inset-0 flex flex-col overflow-hidden bg-slate-50 font-sans">
  <!-- Header -->
  <header
    class="flex w-full items-center justify-between border-b border-slate-200 bg-white px-4 py-1 shadow-sm"
  >
    <div class="flex items-center gap-2">
      <div class="bg-primary text-primary-foreground rounded p-1">
        <ShieldCheck size={20} />
      </div>
      <h1 class="text-xl font-bold tracking-tight text-slate-900">Aroeira</h1>
    </div>
    <div class="text-muted-foreground flex items-center gap-1 text-xs">
      <Lock size={12} />
      <span>Secure Environment</span>
    </div>
  </header>

  <!-- Main Content -->
  <main
    class="flex flex-1 flex-col items-center justify-center overflow-y-auto p-2"
  >
    <Card.Root class="w-full max-w-95 border-slate-200 shadow-lg">
      <Card.Header class="space-y-1 p-4 pb-2">
        <Card.Title class="text-primary text-center text-2xl">
          {isLogin ? "Welcome Back" : "Create Account"}
        </Card.Title>
        <Card.Description class="text-center">
          {isLogin
            ? "Enter your credentials to access your workspace."
            : "Sign up to get started with Aroeira."}
        </Card.Description>
      </Card.Header>
      <Card.Content class="p-4 pt-0">
        <form onsubmit={handleSubmit} class="space-y-2">
          {#if successMessage}
            <div class="text-green-600 text-sm mb-4">
              {successMessage}
            </div>
          {/if}
          <div class="space-y-1">
            <Label for="email" class="text-slate-700">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="name@example.com"
              bind:value={email}
              required
              class="bg-white"
            />
          </div>
          <div class="space-y-1 relative">
            <Label for="password" class="text-slate-700">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="••••••••"
              bind:value={password}
              required
              class="bg-white"
              onfocus={() => (isPasswordFocused = true)}
              onblur={() => (isPasswordFocused = false)}
            />

            {#if !isLogin && isPasswordFocused && !allRulesMet}
              <!-- Floating Password Requirements -->
              <div
                class="absolute left-0 top-full z-50 mt-1 w-full rounded-lg border border-slate-200 bg-white p-3 shadow-xl md:left-full md:ml-4 md:top-0 md:mt-0 md:w-64"
                transition:fly={{ y: -10, duration: 200 }}
              >
                <div
                  class="mb-2 flex items-center justify-between border-b border-slate-100 pb-1"
                >
                  <p class="font-semibold text-xs text-slate-800">
                    Password Requirements
                  </p>
                  <span class="text-[10px] text-slate-400 capitalize"
                    >{policy.level}</span
                  >
                </div>
                <ul class="space-y-1.5 text-xs text-slate-600">
                  <li
                    class="flex items-center gap-2 transition-colors duration-200 {hasMinLength
                      ? 'text-green-600'
                      : ''}"
                  >
                    {#if hasMinLength}
                      <Check size={14} class="stroke-2" />
                    {:else}
                      <Circle size={14} class="stroke-2" />
                    {/if}
                    <span>At least {policy.min_length} characters</span>
                  </li>
                  {#if requiresComplexity}
                    <li
                      class="flex items-center gap-2 transition-colors duration-200 {hasUppercase
                        ? 'text-green-600'
                        : ''}"
                    >
                      {#if hasUppercase}
                        <Check size={14} class="stroke-2" />
                      {:else}
                        <Circle size={14} class="stroke-2" />
                      {/if}
                      <span>One uppercase letter</span>
                    </li>
                    <li
                      class="flex items-center gap-2 transition-colors duration-200 {hasLowercase
                        ? 'text-green-600'
                        : ''}"
                    >
                      {#if hasLowercase}
                        <Check size={14} class="stroke-2" />
                      {:else}
                        <Circle size={14} class="stroke-2" />
                      {/if}
                      <span>One lowercase letter</span>
                    </li>
                    <li
                      class="flex items-center gap-2 transition-colors duration-200 {hasNumber
                        ? 'text-green-600'
                        : ''}"
                    >
                      {#if hasNumber}
                        <Check size={14} class="stroke-2" />
                      {:else}
                        <Circle size={14} class="stroke-2" />
                      {/if}
                      <span>One number</span>
                    </li>
                    <li
                      class="flex items-center gap-2 transition-colors duration-200 {hasSpecial
                        ? 'text-green-600'
                        : ''}"
                    >
                      {#if hasSpecial}
                        <Check size={14} class="stroke-2" />
                      {:else}
                        <Circle size={14} class="stroke-2" />
                      {/if}
                      <span>One special character</span>
                    </li>
                  {/if}
                </ul>
                <!-- Arrow/Caret for visual connection -->
                <div
                  class="absolute -top-1.5 left-4 h-3 w-3 rotate-45 border-l border-t border-slate-200 bg-white md:-left-1.5 md:top-3"
                ></div>
              </div>
            {/if}
          </div>
          {#if !isLogin}
            <div class="space-y-1">
              <Label for="confirm-password" class="text-slate-700"
                >Confirm Password</Label
              >
              <Input
                id="confirm-password"
                type="password"
                placeholder="••••••••"
                bind:value={confirmPassword}
                required
                class="bg-white"
              />
            </div>
          {/if}
          <Button
            type="submit"
            class="w-full font-semibold shadow-md"
            disabled={loading || oauthLoading !== null}
          >
            {#if loading}
              <Loader2 class="mr-2 h-4 w-4 animate-spin" /> Processing...
            {:else}
              {isLogin ? "Sign In" : "Create Account"}
            {/if}
          </Button>
        </form>

        {#if isLogin && oauthAvailability && (oauthAvailability.google || oauthAvailability.github)}
          <!-- OAuth Divider -->
          <div class="relative my-4">
            <div class="absolute inset-0 flex items-center">
              <span class="w-full border-t border-slate-200"></span>
            </div>
            <div class="relative flex justify-center text-xs uppercase">
              <span class="bg-white px-2 text-slate-500">Or continue with</span>
            </div>
          </div>

          <!-- OAuth Buttons -->
          <div class="grid grid-cols-2 gap-3">
            {#if oauthAvailability.google}
              <Button
                type="button"
                variant="outline"
                class="w-full"
                disabled={oauthLoading !== null || loading}
                onclick={() => handleOAuthLogin("google")}
              >
                {#if oauthLoading === "google"}
                  <Loader2 class="mr-2 h-4 w-4 animate-spin" />
                {:else}
                  <svg
                    class="mr-2 h-4 w-4"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      fill="currentColor"
                      d="M21.35 11.1H12v2.95h5.35c-.23 1.5-1.74 4.4-5.35 4.4-3.22 0-5.85-2.66-5.85-5.95S8.78 6.55 12 6.55c1.84 0 3.07.78 3.78 1.45l2.58-2.48C16.9 4.15 14.75 3 12 3 7.03 3 3 7.03 3 12s4.03 9 9 9c5.2 0 8.65-3.65 8.65-8.8 0-.6-.07-1.05-.15-1.1Z"
                    />
                  </svg>
                {/if}
                Google
              </Button>
            {/if}

            {#if oauthAvailability.github}
              <Button
                type="button"
                variant="outline"
                class="w-full"
                disabled={oauthLoading !== null || loading}
                onclick={() => handleOAuthLogin("github")}
              >
                {#if oauthLoading === "github"}
                  <Loader2 class="mr-2 h-4 w-4 animate-spin" />
                {:else}
                  <svg
                    class="mr-2 h-4 w-4"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      fill="currentColor"
                      d="M12 2C6.48 2 2 6.58 2 12.26c0 4.54 2.87 8.39 6.84 9.75.5.1.68-.22.68-.48 0-.24-.01-.87-.01-1.71-2.78.62-3.37-1.38-3.37-1.38-.45-1.2-1.11-1.52-1.11-1.52-.9-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.9 1.56 2.36 1.11 2.94.85.09-.67.35-1.11.63-1.36-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.38-2.03 1-2.74-.1-.26-.44-1.3.1-2.7 0 0 .82-.27 2.7 1.03.78-.22 1.62-.33 2.46-.33.84 0 1.68.11 2.46.33 1.88-1.3 2.7-1.03 2.7-1.03.54 1.4.2 2.44.1 2.7.62.71 1 1.62 1 2.74 0 3.93-2.34 4.8-4.58 5.05.36.32.68.95.68 1.92 0 1.38-.01 2.49-.01 2.83 0 .27.18.59.69.48A10.06 10.06 0 0 0 22 12.26C22 6.58 17.52 2 12 2Z"
                    />
                  </svg>
                {/if}
                GitHub
              </Button>
            {/if}
          </div>
        {/if}
      </Card.Content>
      <Card.Footer
        class="flex flex-col gap-2 rounded-b-lg border-t border-slate-100 bg-slate-50/50 p-3"
      >
        <div class="text-muted-foreground relative w-full text-center text-xs">
          <span class="relative z-10 bg-slate-50/50 px-2">
            {isLogin ? "New to Aroeira?" : "Already have an account?"}
          </span>
          <div class="absolute inset-0 flex items-center">
            <div class="w-full border-t border-slate-200"></div>
          </div>
        </div>
        <Button
          onclick={() => {
            isLogin = !isLogin;
            successMessage = "";
            error = "";
          }}
          class="hover:text-primary w-full border border-slate-200 bg-transparent text-slate-900 shadow-sm hover:bg-white"
        >
          {isLogin ? "Create an account" : "Sign in to your account"}
        </Button>
      </Card.Footer>
    </Card.Root>
  </main>
</div>

{#if error}
  <div
    class="animate-in slide-in-from-top-2 fixed top-6 right-6 z-50 flex w-full max-w-sm items-start gap-4 rounded-lg border border-red-200/60 bg-red-100/80 p-4 text-sm text-red-900 shadow-[0_8px_30px_rgb(0,0,0,0.12)] backdrop-blur-sm sm:right-6 sm:w-auto"
    role="alert"
  >
    <div class="mt-0.5">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="currentColor"
        class="h-5 w-5 text-red-500"
      >
        <path
          fill-rule="evenodd"
          d="M9.401 3.003c1.155-2 4.043-2 5.197 0l7.355 12.748c1.154 2-.29 4.5-2.599 4.5H4.645c-2.309 0-3.752-2.5-2.598-4.5L9.4 3.003zM12 8.25a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V9a.75.75 0 01.75-.75zm0 8.25a.75.75 0 100-1.5.75.75 0 000 1.5z"
          clip-rule="evenodd"
        />
      </svg>
    </div>
    <div class="flex-1 font-medium leading-relaxed">
      {error}
    </div>
    <button
      onclick={dismissError}
      class="text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-900 -mr-2 -mt-2 rounded-md p-2"
      aria-label="Dismiss error"
    >
      <X size={16} />
    </button>
  </div>
{/if}
