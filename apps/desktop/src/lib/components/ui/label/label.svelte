<script lang="ts">
  import { cn } from "$lib/utils";
  import type { Snippet } from "svelte";
  const {
    class: className,
    children,
    ...props
  } = $props<
    {
      class?: string;
      children?: Snippet;
    } & import("svelte/elements").HTMLLabelAttributes
  >();
</script>

<label
  class={cn(
    "text-sm leading-none font-medium peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
    className,
  )}
  {...props}
>
  {@render children?.()}
</label>
