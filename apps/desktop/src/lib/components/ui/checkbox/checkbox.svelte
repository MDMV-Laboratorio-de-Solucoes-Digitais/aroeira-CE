<script lang="ts">
  import { cn } from "$lib/utils";
  let {
    class: className,
    checked = $bindable(),
    ...props
  } = $props<
    {
      class?: string;
      checked?: boolean;
    } & Omit<import("svelte/elements").HTMLInputAttributes, "type">
  >();
</script>

<input
  {...props}
  type="checkbox"
  bind:checked
  class={cn(
    "peer border-input ring-offset-background focus-visible:ring-ring checked:bg-primary checked:text-primary-foreground h-4 w-4 shrink-0 rounded-sm border focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50",
    className,
  )}
/>
