import { vi } from "vitest";

export const goto = vi.fn().mockResolvedValue(true);
export const pushState = vi.fn();
export const replaceState = vi.fn();
export const beforeNavigate = vi.fn();
export const afterNavigate = vi.fn();
export const onNavigate = vi.fn();
export const invalidate = vi.fn().mockResolvedValue(true);
export const invalidateAll = vi.fn().mockResolvedValue(true);
export const preloadData = vi.fn().mockResolvedValue(true);
export const preloadCode = vi.fn().mockResolvedValue(true);
