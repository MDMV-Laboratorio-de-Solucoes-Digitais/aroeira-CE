import { writable } from "svelte/store";
import { browser } from "$app/environment";

export type Theme = "default" | "dark" | "aroeira" | "enterprise";

const STORAGE_KEY = "app-theme";
const DEFAULT_THEME: Theme = "default";

const VALID_THEMES: Theme[] = ["default", "dark", "aroeira", "enterprise"];

function isValidTheme(theme: unknown): theme is Theme {
  return typeof theme === "string" && VALID_THEMES.includes(theme as Theme);
}

function createThemeStore() {
  // Get initial value from localStorage or system preference if needed
  let stored: string | null = null;
  if (browser) {
    try {
      stored = localStorage.getItem(STORAGE_KEY);
    } catch {
      stored = null;
    }
  }
  const initialTheme = isValidTheme(stored) ? stored : DEFAULT_THEME;

  const { subscribe, set } = writable<Theme>(initialTheme);

  const applyTheme = (theme: Theme) => {
    if (!browser) return;

    document.documentElement.removeAttribute("data-theme");
    document.documentElement.classList.remove("dark");

    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else if (theme !== "default") {
      document.documentElement.setAttribute("data-theme", theme);
    }
  };

  // Apply the theme on initial load
  if (browser) {
    applyTheme(initialTheme);
  }

  return {
    subscribe,
    set: (theme: Theme) => {
      if (browser) {
        try {
          localStorage.setItem(STORAGE_KEY, theme);
        } catch {
          // ignore storage failures (fallback to in-memory theme)
        }
      }
      applyTheme(theme);
      set(theme);
    },
  };
}

export const theme = createThemeStore();
