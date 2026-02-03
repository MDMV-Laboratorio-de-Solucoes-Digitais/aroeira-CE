<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/stores";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { invoke } from "@tauri-apps/api/core";
  import { ShieldCheck, ShieldAlert, Loader2, ArrowRight } from "lucide-svelte";
  import { Button } from "$lib/components/ui/button";
  import * as Card from "$lib/components/ui/card";
  import { fly, fade } from "svelte/transition";

  let status = $state<"loading" | "success" | "error">("loading");
  let errorMessage = $state("");

  onMount(async () => {
    const token = $page.url.searchParams.get("token");

    if (!token) {
      status = "error";
      errorMessage =
        "Verification token is missing. Please check your email link.";
      return;
    }

    try {
      await invoke("verify_email", { token });
      status = "success";

      // Auto-redirect after 3 seconds on success
      setTimeout(() => {
        if (status === "success") {
          goto(resolve("/login"));
        }
      }, 3500);
    } catch (err) {
      status = "error";
      errorMessage = err instanceof Error ? err.message : String(err);
    }
  });
</script>

<svelte:head>
  <title>Verifying Email | Ironclad MDMV</title>
</svelte:head>

<div
  class="flex min-h-screen items-center justify-center bg-[conic-gradient(at_top_right,var(--tw-gradient-stops))] from-slate-900 via-slate-800 to-slate-900 p-4 selection:bg-primary/30"
>
  <!-- Background Decorative Elements -->
  <div class="fixed inset-0 overflow-hidden pointer-events-none">
    <div
      class="absolute -top-[10%] -left-[10%] w-[40%] h-[40%] rounded-full bg-primary/5 blur-[120px] animate-pulse"
    ></div>
    <div
      class="absolute -bottom-[10%] -right-[10%] w-[40%] h-[40%] rounded-full bg-blue-500/5 blur-[120px] animate-pulse"
      style="animation-delay: 2s"
    ></div>
  </div>

  <main class="w-full max-w-md perspective-1000">
    <div in:fly={{ y: 20, duration: 800, delay: 100 }}>
      <Card.Root
        class="relative overflow-hidden border-white/10 bg-white/5 shadow-2xl backdrop-blur-xl transition-all duration-500 hover:border-white/20"
      >
        <div
          class="absolute inset-0 bg-linear-to-br from-white/5 to-transparent pointer-events-none"
        ></div>

        <Card.Header class="space-y-1 pb-6 text-center">
          <div
            class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-white/5 shadow-inner ring-1 ring-white/10"
          >
            {#if status === "loading"}
              <div in:fade>
                <Loader2 class="h-8 w-8 animate-spin text-primary" />
              </div>
            {:else if status === "success"}
              <div
                in:fly={{ y: 20, duration: 500 }}
                class="flex items-center justify-center"
              >
                <ShieldCheck
                  class="h-8 w-8 text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]"
                />
              </div>
            {:else}
              <div in:fly={{ y: 20, duration: 500 }}>
                <ShieldAlert
                  class="h-8 w-8 text-rose-400 drop-shadow-[0_0_8px_rgba(251,113,113,0.5)]"
                />
              </div>
            {/if}
          </div>

          <Card.Title class="text-2xl font-bold tracking-tight text-white">
            {#if status === "loading"}
              Verifying your account
            {:else if status === "success"}
              Account Verified!
            {:else}
              Verification Failed
            {/if}
          </Card.Title>
          <Card.Description class="text-slate-400">
            {#if status === "loading"}
              We're securing your credentials and finalizing your access.
            {:else if status === "success"}
              Your email has been successfully verified. Welcome to the
              workspace.
            {:else}
              Something went wrong during the verification process.
            {/if}
          </Card.Description>
        </Card.Header>

        <Card.Content class="space-y-4 pb-8 text-center">
          {#if status === "loading"}
            <div class="flex flex-col gap-2" in:fade>
              <div
                class="h-1.5 w-full overflow-hidden rounded-full bg-white/5 ring-1 ring-white/10"
              >
                <div
                  class="h-full bg-linear-to-r from-primary to-blue-400 shadow-[0_0_10px_rgba(59,130,246,0.5)] transition-all duration-1000 ease-out"
                  style="width: 60%"
                ></div>
              </div>
              <p
                class="text-[10px] uppercase tracking-widest text-slate-500 font-semibold"
              >
                Communicating with secure server...
              </p>
            </div>
          {:else if status === "success"}
            <div in:fly={{ y: 10, duration: 400, delay: 200 }}>
              <p class="text-sm text-slate-300">
                Redirecting you to the login page in a few seconds...
              </p>
            </div>
          {:else}
            <div
              class="rounded-lg border border-rose-500/20 bg-rose-500/10 p-4 text-left"
              in:fly={{ y: 10, duration: 400, delay: 200 }}
            >
              <p class="text-sm italic text-rose-200/90 leading-relaxed">
                "{errorMessage}"
              </p>
            </div>
          {/if}
        </Card.Content>

        <Card.Footer class="flex flex-col gap-3 pt-4">
          {#if status === "success"}
            <Button
              onclick={() => goto(resolve("/login"))}
              class="group w-full bg-primary text-white hover:bg-primary/90 shadow-[0_0_15px_rgba(0,0,0,0.2)] transition-all duration-300"
            >
              Go to Login
              <ArrowRight
                class="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1"
              />
            </Button>
          {:else if status === "error"}
            <Button
              onclick={() => window.location.reload()}
              variant="outline"
              class="w-full border-white/10 bg-white/5 text-white hover:bg-white/10"
            >
              Try Again
            </Button>
            <Button
              variant="ghost"
              onclick={() => goto(resolve("/login"))}
              class="w-full text-slate-400 hover:text-white"
            >
              Back to Sign Up
            </Button>
          {/if}

          <p
            class="text-center text-[10px] tracking-wide text-slate-500 uppercase font-medium"
          >
            Ironclad MDMV Security Protocol
          </p>
        </Card.Footer>
      </Card.Root>
    </div>
  </main>
</div>

<style>
  .perspective-1000 {
    perspective: 1000px;
  }
</style>
