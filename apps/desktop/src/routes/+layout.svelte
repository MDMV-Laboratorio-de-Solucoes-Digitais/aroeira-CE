<script lang="ts">
  import "../app.css";
  import LayoutShell from "$lib/components/layout/LayoutShell.svelte";

  let { children } = $props();
</script>

<LayoutShell>
  {@render children()}
</LayoutShell>
