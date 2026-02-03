import { type, type OsType } from "@tauri-apps/plugin-os";

let platformCache: Promise<OsType | "unknown"> | null = null;

function getPlatformType(): Promise<OsType | "unknown"> {
  if (platformCache === null) {
    const promise = (async () => {
      // SSR / non-browser guard
      if (typeof window === "undefined") return "unknown";

      try {
        return await type();
      } catch (e) {
        // Treat failures as "unknown" but don't spam logs.
        console.debug(
          "Platform detection failed; falling back to 'unknown':",
          e instanceof Error ? e.message : String(e),
        );
        return "unknown";
      }
    })();

    platformCache = promise;
    promise.then((resolved) => {
      if (resolved === "unknown") {
        // Add a small delay before allowing a retry to prevent spamming failed calls.
        setTimeout(() => {
          if (platformCache === promise) {
            platformCache = null;
          }
        }, 1000);
      }
    });
  }
  return platformCache;
}

/**
 * Detects if current platform is a desktop environment (Windows, macOS, Linux).
 */
export async function isDesktop(): Promise<boolean> {
  const p = await getPlatformType();
  return p === "windows" || p === "macos" || p === "linux";
}

/**
 * Detects if current platform is a mobile environment (Android, iOS).
 */
export async function isMobile(): Promise<boolean> {
  const p = await getPlatformType();
  return p === "android" || p === "ios";
}

/**
 * Returns specific platform type.
 */
export async function getPlatform(): Promise<OsType | "unknown"> {
  return getPlatformType();
}

/**
 * Helper to check if we are on macOS specifically (for window controls).
 */
export async function isMacOS(): Promise<boolean> {
  return (await getPlatformType()) === "macos";
}

/**
 * Helper to check if we are on Windows specifically (for custom titlebar).
 */
export async function isWindows(): Promise<boolean> {
  return (await getPlatformType()) === "windows";
}
