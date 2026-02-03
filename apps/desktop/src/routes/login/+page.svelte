<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { fly } from "svelte/transition";
  import { Button } from "$lib/components/ui/button";
  import * as Card from "$lib/components/ui/card";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { invoke } from "@tauri-apps/api/core";
  import { Lock, ShieldCheck, X, Check, Circle, Loader2 } from "lucide-svelte";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { logAuditEvent, setSessionId } from "$lib/audit";
  import { handleError } from "$lib/logger";
  import {
    startOAuthFlow,
    handleOAuthCallback,
    type OAuthProvider,
  } from "$lib/oauth";
  import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
  import type { UnlistenFn } from "@tauri-apps/api/event";

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
  let error = $state("");
  let successMessage = $state("");
  let email = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let isPasswordFocused = $state(false);
  let unlistenDeepLink: UnlistenFn | null = null;

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

  // Guard against concurrent OAuth callback processing to prevent race conditions
  let oauthCallbackInFlight = $state(false);

  /**
   * Process an OAuth callback URL from deep linking.
   * This handles the aroeira://auth/callback URLs.
   */
  async function processOAuthCallback(rawUrl: string): Promise<void> {
    // Prevent concurrent callback processing from multiple deep-link events
    if (oauthCallbackInFlight) return;

    // Defensive bound to avoid processing extremely large deep-link payloads
    if (rawUrl.length > 8192) return;

    // The backend performs robust validation of the callback URL.
    // We only do a basic check here to avoid invoking the backend for unrelated deep links.
    if (!rawUrl.startsWith("aroeira:")) {
      return;
    }

    // Set in-flight guard before any async operations
    oauthCallbackInFlight = true;

    // Restore loading state from localStorage if not already set
    // This handles cold start scenarios where the app was closed
    if (!oauthLoading) {
      const savedProvider = localStorage.getItem("oauth_pending_provider");
      // Validate provider to ensure UI state is correct
      oauthLoading =
        savedProvider === "google" || savedProvider === "github"
          ? (savedProvider as OAuthProvider)
          : null;

      // Clear invalid state if any
      if (!oauthLoading && savedProvider) {
        localStorage.removeItem("oauth_pending_provider");
      }
    }
    error = "";

    try {
      const user = await handleOAuthCallback(rawUrl);
      logAuditEvent("oauth_login", true, {
        provider: user.provider,
        email: redactEmail(user.email),
      });
      setSessionId();
      localStorage.removeItem("oauth_pending_provider");
      await goto(resolve("/dashboard"), { replaceState: true });
    } catch (err: unknown) {
      logAuditEvent("oauth_login", false, {
        error: sanitizeErrorForAudit(err),
      });
      error = handleError(err, "OAuth authentication");
    } finally {
      oauthLoading = null;
      oauthCallbackInFlight = false;
      localStorage.removeItem("oauth_pending_provider");
    }
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
        for (const url of urls) {
          await processOAuthCallback(url);
        }
      });
    } catch (err) {
      console.error(
        "Failed to setup deep link listener",
        sanitizeErrorForAudit(err),
      );
    }
  });

  onDestroy(() => {
    if (unlistenDeepLink) {
      unlistenDeepLink();
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
    oauthLoading = provider;
    error = "";

    // Save provider to localStorage for cold start recovery
    localStorage.setItem("oauth_pending_provider", provider);

    try {
      await startOAuthFlow(provider);
      // The browser will open and redirect back via deep link
      // The callback is handled by processOAuthCallback
    } catch (err: unknown) {
      logAuditEvent("oauth_start", false, {
        provider,
        error: sanitizeErrorForAudit(err),
      });
      error = handleError(err, `${provider} authentication`);
      oauthLoading = null;
      localStorage.removeItem("oauth_pending_provider");
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

        {#if isLogin}
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
                <svg class="mr-2 h-4 w-4" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="currentColor"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                  />
                </svg>
              {/if}
              Google
            </Button>
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
                <svg class="mr-2 h-4 w-4" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"
                  />
                </svg>
              {/if}
              GitHub
            </Button>
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
