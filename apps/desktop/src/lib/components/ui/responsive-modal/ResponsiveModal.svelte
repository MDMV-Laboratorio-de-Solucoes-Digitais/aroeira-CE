<script lang="ts">
  import { Button } from "$lib/components/ui/button";
  import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
  } from "$lib/components/ui/dialog";
  import * as Drawer from "$lib/components/ui/drawer";
  import { isMobile } from "$lib/utils/platform";
  import { onMount } from "svelte";

  import type { Snippet } from "svelte";

  interface Props {
    open?: boolean;
    title?: string;
    description?: string | Snippet;
    children?: Snippet;
    footer?: Snippet;
  }

  let {
    open = $bindable(false),
    title,
    description,
    children,
    footer,
  }: Props = $props();

  let mobile = $state(false);

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
</script>

{#if mobile}
  <Drawer.Root bind:open>
    <Drawer.Content>
      <Drawer.Header class="text-left">
        {#if title}
          <Drawer.Title>{title}</Drawer.Title>
        {/if}
        {#if description}
          <Drawer.Description>
            {#if typeof description === "string"}
              {description}
            {:else}
              {@render description()}
            {/if}
          </Drawer.Description>
        {/if}
      </Drawer.Header>

      <div class="px-4">
        {@render children?.()}
      </div>

      <Drawer.Footer class="pt-2">
        {#if footer}
          {@render footer()}
        {:else}
          <Drawer.Close>
            {#snippet child({ props })}
              <Button variant="outline" class="w-full" {...props}>Close</Button>
            {/snippet}
          </Drawer.Close>
        {/if}
      </Drawer.Footer>
    </Drawer.Content>
  </Drawer.Root>
{:else}
  <Dialog bind:open>
    <DialogContent class="sm:max-w-[26.5625rem]">
      <DialogHeader>
        {#if title}
          <DialogTitle>{title}</DialogTitle>
        {/if}
        {#if description}
          <DialogDescription>
            {#if typeof description === "string"}
              {description}
            {:else}
              {@render description()}
            {/if}
          </DialogDescription>
        {/if}
      </DialogHeader>

      {@render children?.()}

      <DialogFooter>
        {#if footer}
          {@render footer()}
        {:else}
          <DialogClose>
            {#snippet child({ props })}
              <Button variant="outline" {...props}>Close</Button>
            {/snippet}
          </DialogClose>
        {/if}
      </DialogFooter>
    </DialogContent>
  </Dialog>
{/if}
