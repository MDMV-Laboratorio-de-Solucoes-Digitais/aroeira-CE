import * as matchers from "@testing-library/jest-dom/matchers";
import { expect, vi } from "vitest";

expect.extend(matchers);

// eslint-disable-next-line no-undef
if (process.env.DEBUG_TEST_SETUP) {
  console.log("SETUP TESTS RUNNING (Manual Extend)");
}

const matchMediaMock = vi.fn().mockImplementation((query) => ({
  matches: false,
  media: query,
  onchange: null,
  addListener: vi.fn(), // deprecated
  removeListener: vi.fn(), // deprecated
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
}));

vi.stubGlobal("matchMedia", matchMediaMock);

class LocalStorageMock {
  private store: Record<string, string> = {};

  get length(): number {
    return Object.keys(this.store).length;
  }

  getItem(key: string): string | null {
    return key in this.store ? this.store[key] : null;
  }

  setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }

  removeItem(key: string): void {
    delete this.store[key];
  }

  clear(): void {
    this.store = {};
  }

  key(index: number): string | null {
    const keys = Object.keys(this.store);
    return index >= 0 && index < keys.length ? keys[index] : null;
  }
}

const localStorageMock = new LocalStorageMock();

vi.stubGlobal("localStorage", localStorageMock);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// Mock navigation
vi.mock("$app/navigation", () => ({
  goto: vi.fn(),
}));

// Mock Web Animations API for Svelte transitions
Element.prototype.animate = vi.fn().mockImplementation(() => ({
  finished: Promise.resolve(),
  cancel: vi.fn(),
  play: vi.fn(),
  pause: vi.fn(),
  reverse: vi.fn(),
  onfinish: null,
}));
