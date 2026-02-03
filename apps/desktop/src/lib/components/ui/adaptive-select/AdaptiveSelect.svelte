<script lang="ts">
  import { onMount } from "svelte";
  import { isMobile } from "$lib/utils/platform";
  import * as Select from "$lib/components/ui/select";
  import * as Drawer from "$lib/components/ui/drawer";
  import { Button } from "$lib/components/ui/button";

  interface Props {
    value?: string;
    options?: { value: string; label: string }[];
    placeholder?: string;
  }

  let {
    value = $bindable(),
    options = [],
    placeholder = "Select option",
  }: Props = $props();

  let mobile = $state(false);
  let open = $state(false);

  let selectedLabel = $derived(
    options.find((o) => o.value === value)?.label || placeholder,
  );

  onMount(() => {
    let aborted = false;

    (async () => {
      try {
        const m = await isMobile();
        if (!aborted) mobile = m;
      } catch {
        if (!aborted) mobile = false;
      }
    })();

    return () => {
      aborted = true;
    };
  });

  function handleSelect(val: string) {
    value = val;
    open = false;
  }
</script>

{#if mobile}
  <Drawer.Root bind:open>
    <Drawer.Trigger>
      {#snippet child({ props })}
        <Button
          variant="outline"
          {...props}
          class="w-full justify-start text-left font-normal"
        >
          {selectedLabel}
        </Button>
      {/snippet}
    </Drawer.Trigger>
    <Drawer.Content>
      <div class="mt-4 border-t">
        <div class="p-4 space-y-2">
          {#each options as option (option.value)}
            <button
              type="button"
              class="w-full text-left px-4 py-3 rounded-md active:bg-accent text-lg font-medium flex items-center justify-between"
              class:bg-accent={value === option.value}
              onclick={() => handleSelect(option.value)}
            >
              {option.label}
              {#if value === option.value}
                <span class="text-primary">✓</span>
              {/if}
            </button>
          {/each}
        </div>
      </div>
      <Drawer.Footer class="pt-2">
        <Drawer.Close>
          {#snippet child({ props })}
            <Button variant="outline" {...props}>Cancel</Button>
          {/snippet}
        </Drawer.Close>
      </Drawer.Footer>
    </Drawer.Content>
  </Drawer.Root>
{:else}
  <Select.Root type="single" bind:value>
    <Select.Trigger class="w-full">
      {selectedLabel}
    </Select.Trigger>
    <Select.Content>
      {#each options as option (option.value)}
        <Select.Item value={option.value}>{option.label}</Select.Item>
      {/each}
    </Select.Content>
  </Select.Root>
{/if}
