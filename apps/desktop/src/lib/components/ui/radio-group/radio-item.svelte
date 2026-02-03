<script lang="ts">
  import { cn } from "$lib/utils";
  let {
    class: className,
    value,
    group = $bindable(),
    ...props
  } = $props<
    {
      class?: string;
      value: string;
      group?: string | number;
    } & import("svelte/elements").HTMLInputAttributes
  >();
</script>

<input
  type="radio"
  {value}
  bind:group
  class={cn(
    "border-input ring-offset-background focus:ring-ring aspect-square h-4 w-4 rounded-full border focus:ring-2 focus:ring-offset-2 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50",
    className,
  )}
  {...props}
/>
