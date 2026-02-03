<script lang="ts">
  import { cn } from "$lib/utils";
  const { class: className, ...props } =
    $props<import("svelte/elements").HTMLAttributes<HTMLDivElement>>();
</script>

<div
  class={cn("bg-muted animate-pulse rounded-md", className)}
  {...props}
></div>
