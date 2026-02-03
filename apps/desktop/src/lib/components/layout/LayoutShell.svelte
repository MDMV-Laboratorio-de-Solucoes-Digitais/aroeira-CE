<script lang="ts">
  import { onMount } from "svelte";
  import { isMobile, isDesktop, isWindows, isMacOS } from "$lib/utils/platform";
  import Sidebar from "./Sidebar.svelte";
  import BottomNav from "./BottomNav.svelte";
  import TitleBar from "./TitleBar.svelte";
  import { ScrollArea } from "$lib/components/ui/scroll-area";

  let mobile = $state(false);
  let desktop = $state(false);
  let mac = $state(false);
  let windows = $state(false);
  let loading = $state(true);

  let { children } = $props();

  onMount(() => {
    let aborted = false;

    const withTimeout = <T,>(p: Promise<T>, ms: number) =>
      new Promise<T>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("Platform detection timeout")),
          ms,
        );

        p.then(resolve, reject).finally(() => clearTimeout(timer));
      });

    (async () => {
      try {
        const [isMob, isDesk, isMac, isWin] = await withTimeout(
          Promise.all([isMobile(), isDesktop(), isMacOS(), isWindows()]),
          1500,
        );

        if (aborted) return;

        mobile = isMob;
        desktop = isDesk;
        mac = isMac;
        windows = isWin;

        if (!mobile && !desktop) {
          desktop = true;
        }
      } catch (err) {
        if (aborted) return;
        console.warn(
          "Platform detection failed, falling back to desktop:",
          err,
        );
        mobile = false;
        desktop = true;
        mac = false;
        windows = false;
      } finally {
        if (!aborted) loading = false;
      }
    })();

    return () => {
      aborted = true;
    };
  });
</script>

<svelte:head>
  {#if mobile}
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover"
    />
  {/if}
</svelte:head>

<!-- Global Shell -->
<div class="global-shell bg-background text-foreground h-full w-full">
  {#if loading}
    <div class="h-screen w-screen flex items-center justify-center">
      <!-- Loading State / Splash -->
    </div>
  {:else if desktop}
    <div class="flex flex-col h-screen w-screen overflow-hidden">
      <!-- Windows Custom TitleBar (Hide on Linux/Mac where we use native) -->
      {#if windows}
        <TitleBar />
      {/if}

      <!-- Main Workspace (Sidebar + Content) -->
      <div class="flex flex-1 overflow-hidden">
        <!-- Sidebar -->
        <Sidebar isMac={mac} />

        <!-- Main Content Area -->
        <main class="flex-1 flex flex-col min-w-0 relative bg-background">
          <ScrollArea class="h-full w-full">
            <div class="p-6 container mx-auto max-w-7xl">
              {@render children()}
            </div>
          </ScrollArea>
        </main>
      </div>
    </div>
  {:else if mobile}
    <div class="flex flex-col min-h-screen pb-safe">
      <!-- Mobile Status Bar spacer could go here if needed -->

      <main class="flex-1 pb-20 px-4 pt-safe">
        {@render children()}
      </main>

      <BottomNav />
    </div>
  {/if}
</div>
