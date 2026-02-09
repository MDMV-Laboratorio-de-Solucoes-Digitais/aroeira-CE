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
    // 0-31 are control codes, 127 is DEL. \s checks for whitespace.
    if (code <= 31 || code === 127 || /\s/.test(href[start])) {
      start++;
    } else {
      break;
    }
  }
  const normalized = href.slice(start);
  if (normalized.startsWith("//")) return true;

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/i.exec(normalized);
  if (!schemeMatch) return false;

  const scheme = schemeMatch[1].toLowerCase();
  return !ALLOWED_EXTERNAL_SCHEMES.has(scheme);
}
