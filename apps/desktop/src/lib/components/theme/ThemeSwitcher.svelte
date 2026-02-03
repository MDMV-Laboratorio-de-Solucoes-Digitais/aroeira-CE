<script lang="ts">
  import { theme, type Theme } from "$lib/utils/theme";
  import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
  import { Palette } from "lucide-svelte";

  function setTheme(t: Theme) {
    theme.set(t);
  }
</script>

<DropdownMenu.Root>
  <DropdownMenu.Trigger>
    {#snippet child({ props })}
      <button
        type="button"
        {...props}
        class="inline-flex items-center justify-center rounded-md text-sm transition-none focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 h-9 w-9 hover:bg-accent text-foreground"
      >
        <Palette class="h-[1.2rem] w-[1.2rem]" />
        <span class="sr-only">Toggle theme</span>
      </button>
    {/snippet}
  </DropdownMenu.Trigger>
  <DropdownMenu.Content align="end">
    <DropdownMenu.Item
      onclick={() => setTheme("default")}
      class="font-light text-muted-foreground data-highlighted:text-foreground cursor-pointer"
      >Default (Light)</DropdownMenu.Item
    >
    <DropdownMenu.Item
      onclick={() => setTheme("dark")}
      class="font-light text-muted-foreground data-highlighted:text-foreground cursor-pointer"
      >Dark</DropdownMenu.Item
    >
    <DropdownMenu.Item
      onclick={() => setTheme("aroeira")}
      class="font-light text-muted-foreground data-highlighted:text-foreground cursor-pointer"
      >Aroeira</DropdownMenu.Item
    >
    <DropdownMenu.Item
      onclick={() => setTheme("enterprise")}
      class="font-light text-muted-foreground data-highlighted:text-foreground cursor-pointer"
      >Enterprise</DropdownMenu.Item
    >
  </DropdownMenu.Content>
</DropdownMenu.Root>
