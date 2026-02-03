<script lang="ts">
  import { navItems } from "$lib/navigation";
  import { page } from "$app/stores";
  import { base } from "$app/paths";

  let currentPath = $derived($page.url.pathname);

  const withBase = (path: string) => (base ? `${base}${path}` : path);
</script>

<nav
  class="fixed bottom-0 left-0 right-0 border-t bg-background/80 backdrop-blur-lg pb-safe z-50"
>
  <div class="flex items-center justify-around h-16 px-2">
    {#each navItems as item (item.href)}
      <a
        href={withBase(item.href)}
        class="flex flex-col items-center justify-center w-full h-full space-y-1 text-xs text-muted-foreground hover:text-primary data-[active=true]:text-primary"
        data-active={currentPath === item.href}
      >
        <item.icon class="w-5 h-5" />
        <span>{item.label}</span>
      </a>
    {/each}
  </div>
</nav>
