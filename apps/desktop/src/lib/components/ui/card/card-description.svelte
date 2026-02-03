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
    } & import("svelte/elements").HTMLAttributes<HTMLParagraphElement>
  >();
</script>

<p class={cn("text-muted-foreground text-sm", className)} {...props}>
  {@render children?.()}
</p>
