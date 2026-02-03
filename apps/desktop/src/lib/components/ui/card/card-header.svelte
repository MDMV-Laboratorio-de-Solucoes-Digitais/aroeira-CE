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

<div class={cn("flex flex-col space-y-1.5 p-6", className)} {...props}>
  {@render children?.()}
</div>
