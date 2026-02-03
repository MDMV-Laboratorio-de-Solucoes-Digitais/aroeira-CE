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
    } & import("svelte/elements").HTMLAttributes<HTMLDivElement>
  >();
</script>

<div
  class={cn(
    "bg-card text-card-foreground rounded-lg border shadow-sm",
    className,
  )}
  {...props}
>
  {@render children?.()}
</div>
