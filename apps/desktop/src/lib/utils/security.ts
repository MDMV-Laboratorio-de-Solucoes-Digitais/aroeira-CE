/**
 * Set of URL schemes allowed for external links.
 * Used to prevent dangerous schemes like 'javascript:' or 'data:'.
 */
export const ALLOWED_EXTERNAL_SCHEMES = new Set([
  "http",
  "https",
  "mailto",
  "tel",
]);

/**
 * Checks if a URL has a dangerous scheme or is protocol-relative.
 */
export function isDangerousHref(href: string): boolean {
  // Normalize by trimming leading whitespace and control characters to prevent bypasses
  // Use trimStart() to remove Unicode whitespace, then manually strip ASCII control chars.
  let normalized = href.trimStart();

  let start = 0;
  while (start < normalized.length) {
    const code = normalized.charCodeAt(start);
    // Strip leading ASCII controls: 0x00-0x1F, 0x7F (DEL)
    if (!(code <= 0x1f || code === 0x7f)) break;
    start++;
  }
  normalized = normalized.slice(start);
  if (normalized.startsWith("//")) return true;

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/i.exec(normalized);
  if (!schemeMatch) return false;

  const scheme = schemeMatch[1].toLowerCase();
  return !ALLOWED_EXTERNAL_SCHEMES.has(scheme);
}
