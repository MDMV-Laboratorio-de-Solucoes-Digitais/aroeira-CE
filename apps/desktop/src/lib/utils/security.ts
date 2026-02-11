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
  // Manual loop to avoid no-control-regex lint error
  let start = 0;
  while (start < href.length) {
    const code = href.charCodeAt(start);

    // Trim leading ASCII control chars + common whitespace to prevent scheme-bypass tricks.
    // Controls: 0x00-0x1F, 0x7F (DEL)
    // Whitespace: 0x20 (space), 0x09-0x0D (tab/newlines), 0xA0 (NBSP), 0xFEFF (BOM)
    const isLeadingJunk =
      code <= 0x1f ||
      code === 0x7f ||
      code === 0x20 ||
      (code >= 0x09 && code <= 0x0d) ||
      code === 0x00a0 ||
      code === 0xfeff;

    if (!isLeadingJunk) break;
    start++;
  }
  const normalized = href.slice(start);
  if (normalized.startsWith("//")) return true;

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/i.exec(normalized);
  if (!schemeMatch) return false;

  const scheme = schemeMatch[1].toLowerCase();
  return !ALLOWED_EXTERNAL_SCHEMES.has(scheme);
}
