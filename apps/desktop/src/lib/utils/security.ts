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
  let normalized = href;
  try {
    normalized = href.normalize("NFKC");
  } catch (e) {
    // Fallback: If normalization fails, process the original string to avoid throwing errors.
    if (import.meta.env.DEV) {
      console.warn(`[Security] Failed to normalize href: "${href}"`, e);
    }
    normalized = href;
  }
  normalized = normalized.trimStart();

  // Strip leading Unicode format/invisible chars that can be used for obfuscation (e.g., BOM/ZW*).
  // This is a defense-in-depth measure against homograph/spoofing attacks.
  normalized = normalized.replace(
    /^[\uFEFF\u200B-\u200F\u2060\u2066-\u2069]+/g,
    "",
  );

  let start = 0;
  while (start < normalized.length) {
    const code = normalized.charCodeAt(start);
    // Strip leading ASCII controls: 0x00-0x1F, 0x7F (DEL)
    if (!(code <= 0x1f || code === 0x7f)) break;
    start++;
  }
  normalized = normalized.slice(start);

  // Strip all remaining ASCII control chars to avoid scheme obfuscation like "java\u0000script:".
  // eslint-disable-next-line no-control-regex
  normalized = normalized.replace(/[\u0000-\u001F\u007F]/g, "");

  // Harden scheme detection by removing whitespace/invisible chars from scheme portion.
  const colonIndex = normalized.indexOf(":");

  // Reject percent-encoded ASCII controls/whitespace used for scheme obfuscation.
  // Only scan the potential scheme prefix to avoid false positives in path/query (e.g. "%20" in URLs).
  const prefixEnd =
    colonIndex !== -1 ? colonIndex + 1 : Math.min(normalized.length, 64);
  const schemePrefix = normalized.slice(0, prefixEnd);

  const hasEncodedControlsOrWs =
    /%(0[0-9a-f]|1[0-9a-f]|7f)/i.test(schemePrefix) ||
    /%(09|0a|0b|0c|0d|20)/i.test(schemePrefix);
  if (hasEncodedControlsOrWs) return true;

  // Backslash can be interpreted/normalized inconsistently by parsers and used for obfuscation.
  // Fail closed: treat any backslash as dangerous rather than rewriting it.
  if (normalized.includes("\\")) return true;

  if (normalized.startsWith("//")) return true;

  const schemeCandidate =
    colonIndex === -1
      ? normalized
      : normalized
          .slice(0, colonIndex)
          .replace(/[\s\uFEFF\u200B-\u200F\u2060\u2066-\u2069]+/g, "") + ":";

  // Reject percent-encoding inside the scheme token itself (e.g. "java%73cript:").
  if (schemeCandidate.includes("%")) return true;

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/i.exec(schemeCandidate);
  if (!schemeMatch) return false;

  const scheme = schemeMatch[1].toLowerCase();
  return !ALLOWED_EXTERNAL_SCHEMES.has(scheme);
}
