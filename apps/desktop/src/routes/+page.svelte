<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { invoke } from "@tauri-apps/api/core";
  import { logError } from "$lib/logger";

  onMount(async () => {
    try {
      // Use lightweight has_auth_token command instead of expensive get_notes
      // This separates "auth valid" from "notes fetch works"
      const hasToken = await invoke<boolean>("has_auth_token");
      if (hasToken) {
        await goto(resolve("/dashboard"), { replaceState: true });
      } else {
        await goto(resolve("/login"), { replaceState: true });
      }
    } catch (error) {
      // Log error securely without exposing sensitive data
      logError("auth_check", error);
      // On transient backend errors, redirect to login for safety
      await goto(resolve("/login"), { replaceState: true });
    }
  });
</script>

<div
  class="flex flex-col items-center justify-center min-h-screen font-sans text-base"
>
  <p class="text-[#646cff] font-medium">Checking authentication...</p>
</div>
