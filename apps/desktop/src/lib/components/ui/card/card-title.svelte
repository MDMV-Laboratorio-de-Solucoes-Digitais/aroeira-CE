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
    } & import("svelte/elements").HTMLAttributes<HTMLHeadingElement>
  >();
</script>

<h3
  class={cn("text-2xl leading-none font-semibold tracking-tight", className)}
  {...props}
>
  {@render children?.()}
</h3>
