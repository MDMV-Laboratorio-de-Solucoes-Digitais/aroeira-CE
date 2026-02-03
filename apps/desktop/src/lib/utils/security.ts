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
  // eslint-disable-next-line no-control-regex
  const normalized = href.replace(/^[\s\u0000-\u001F\u007F]+/g, "");
  if (normalized.startsWith("//")) return true;

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/i.exec(normalized);
  if (!schemeMatch) return false;

  const scheme = schemeMatch[1].toLowerCase();
  return !ALLOWED_EXTERNAL_SCHEMES.has(scheme);
}
