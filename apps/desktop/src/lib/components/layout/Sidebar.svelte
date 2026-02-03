<script lang="ts">
  import { navItems } from "$lib/navigation";
  import { page } from "$app/stores";
  import { config } from "$lib/config";
  import ThemeSwitcher from "$lib/components/theme/ThemeSwitcher.svelte";
  import { base } from "$app/paths";

  let currentPath = $derived($page.url.pathname);

  // Example props
  let { isMac = false } = $props();

  const withBase = (path: string) => (base ? `${base}${path}` : path);
</script>

<aside
  class="w-64 border-r h-full flex flex-col bg-background/50 backdrop-blur-sm"
  class:pt-10={isMac}
>
  <div class="p-6">
    <h1 class="font-bold text-xl tracking-tight">Aroeira</h1>
  </div>
  <nav class="flex-1 px-4 space-y-2">
    {#each navItems as item (item.href)}
      <a
        href={withBase(item.href)}
        class="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-accent text-muted-foreground hover:text-foreground data-[active=true]:bg-accent data-[active=true]:text-foreground transition-colors"
        data-active={currentPath === item.href}
      >
        <item.icon class="w-4 h-4" />
        {item.label}
      </a>
    {/each}
  </nav>
  {#if config.theme.enableSwitcher}
    <div class="p-4 border-t">
      <ThemeSwitcher />
    </div>
  {/if}
</aside>
