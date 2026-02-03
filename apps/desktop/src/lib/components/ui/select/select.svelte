<script lang="ts">
  import { Select as SelectPrimitive } from "bits-ui";

  let {
    open = $bindable(false),
    value = $bindable(),
    ...restProps
  }: SelectPrimitive.RootProps = $props();

  let internalValue = $state<string | undefined>(value as string | undefined);
  let syncing = $state(false);

  const releaseSync = () => queueMicrotask(() => (syncing = false));

  // Sync down when external value changes
  // Two-way sync is necessary because bits-ui's SelectPrimitive manages its own internal state
  // while we also want to allow external value binding. Without the syncing flag and dual effects,
  // we would create infinite update loops when the external value changes or when bits-ui emits selection changes.
  $effect(() => {
    if (syncing) return;
    if (internalValue !== value) {
      syncing = true;
      internalValue = value as string | undefined;
      releaseSync();
    }
  });

  // Sync up when bits-ui changes
  $effect(() => {
    if (syncing) return;
    if (value !== internalValue) {
      syncing = true;
      value = internalValue as string | undefined;
      releaseSync();
    }
  });

  const filteredProps = $derived(
    Object.fromEntries(
      Object.entries(restProps).filter(([k]) => k !== "value" && k !== "open"),
    ) as Record<string, unknown>,
  );
</script>

<SelectPrimitive.Root
  type="single"
  bind:open
  bind:value={internalValue}
  {...filteredProps}
/>
