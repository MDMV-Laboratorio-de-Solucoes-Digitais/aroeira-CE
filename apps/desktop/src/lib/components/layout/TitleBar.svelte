<script lang="ts">
  import { onMount } from "svelte";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { Minimize, Maximize, X } from "lucide-svelte";

  let appWindow: ReturnType<typeof getCurrentWindow> | null = null;

  onMount(() => {
    try {
      appWindow = getCurrentWindow();
    } catch {
      appWindow = null;
    }
  });

  function minimize() {
    if (!appWindow) return;
    appWindow.minimize().catch((e) => console.error("Failed to minimize", e));
  }

  function maximize() {
    if (!appWindow) return;
    appWindow
      .toggleMaximize()
      .catch((e) => console.error("Failed to maximize", e));
  }

  function close() {
    if (!appWindow) return;
    appWindow.close().catch((e) => console.error("Failed to close", e));
  }
</script>

<div
  class="relative h-8 w-full bg-background border-b select-none flex items-center justify-between"
>
  <!-- Drag Region Layer -->
  <div data-tauri-drag-region class="absolute inset-0 z-0"></div>

  <!-- Content Layer -->
  <div class="relative z-10 flex h-full items-center px-4 pointer-events-none">
    <span class="text-xs font-medium text-muted-foreground">Aroeira</span>
  </div>

  <div class="relative z-10 flex h-full items-center mr-2 space-x-1">
    <button
      class="inline-flex justify-center items-center w-8 h-6 rounded-sm hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-colors pointer-events-auto"
      onclick={minimize}
      title="Minimize"
    >
      <Minimize class="w-3.5 h-3.5" />
    </button>
    <button
      class="inline-flex justify-center items-center w-8 h-6 rounded-sm hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-colors pointer-events-auto"
      onclick={maximize}
      title="Maximize"
    >
      <Maximize class="w-3.5 h-3.5" />
    </button>
    <button
      class="inline-flex justify-center items-center w-8 h-6 rounded-sm hover:bg-red-500 hover:text-white transition-colors pointer-events-auto"
      onclick={close}
      title="Close"
    >
      <X class="w-3.5 h-3.5" />
    </button>
  </div>
</div>
