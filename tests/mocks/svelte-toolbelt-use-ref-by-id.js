// Mock for svelte-toolbelt use-ref-by-id.svelte.js
export function useRefById({ id, ref, getRootNode }) {
  // Mock implementation: try once immediately
  try {
    const _id = id && id.current;
    if (_id) {
      const rootNode =
        (getRootNode && getRootNode()) ||
        (typeof document !== "undefined" ? document : null);
      const node = rootNode && rootNode.getElementById(_id);
      if (node && ref) {
        ref.current = node;
      }
    }
  } catch {
    // Silently ignore errors in mock
  }
}
