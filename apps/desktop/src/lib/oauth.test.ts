import { describe, it, expect, vi, beforeEach } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { goto } from "$app/navigation";
import { processOAuthCallback } from "./oauth";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("./logger", () => ({
  handleError: vi.fn((err: unknown, _context: string) => {
    return String(err);
  }),
}));

vi.mock("./audit", () => ({
  logAuditEvent: vi.fn(),
  setSessionId: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(),
}));

describe("processOAuthCallback - redirect_uri security", () => {
  const mockCallbacks = {
    setLoading: vi.fn(),
    setError: vi.fn(),
    resetState: vi.fn(),
  };

  const mockGetLoadingState = vi.fn(() => "google" as const);

  const validCode = "auth_code_xyz789";

  // Helper to create unique state for each test to avoid deduplication conflicts
  const createUniqueState = (testId: string) =>
    `test_state_${testId}_${Date.now()}`;

  const setupLocalStorage = (state: string) => {
    localStorage.setItem("oauth_pending_provider", "google");
    localStorage.setItem("oauth_pending_state", state);
    localStorage.setItem("oauth_pending_started_at", String(Date.now()));
  };

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();

    vi.mocked(invoke).mockResolvedValue({
      provider: "google",
      email: "test@example.com",
      name: "Test User",
      avatar_url: "https://example.com/avatar.jpg",
    });

    vi.mocked(goto).mockResolvedValue(undefined);
  });

  describe("redirect_uri validation", () => {
    it("should reject callback with unexpected redirect_uri parameter", async () => {
      const state = createUniqueState("reject_unexpected");
      setupLocalStorage(state);
      const url = `aroeira://auth/callback?code=${validCode}&state=${state}&redirect_uri=https://evil.com/callback`;

      await processOAuthCallback(url, mockCallbacks, mockGetLoadingState);

      expect(mockCallbacks.resetState).toHaveBeenCalledWith(
        "Authentication callback was invalid. Please try again.",
      );

      expect(invoke).not.toHaveBeenCalled();

      expect(goto).not.toHaveBeenCalled();
    });

    it("should accept callback without redirect_uri parameter", async () => {
      const state = createUniqueState("accept_no_redirect");
      setupLocalStorage(state);
      const url = `aroeira://auth/callback?code=${validCode}&state=${state}`;

      await processOAuthCallback(url, mockCallbacks, mockGetLoadingState);

      expect(mockCallbacks.resetState).not.toHaveBeenCalledWith(
        expect.stringContaining("invalid"),
      );

      expect(invoke).toHaveBeenCalled();

      expect(goto).toHaveBeenCalled();
    });

    it("should accept callback with standard aroeira scheme redirect_uri", async () => {
      const state = createUniqueState("accept_standard");
      setupLocalStorage(state);
      const url = `aroeira://auth/callback?code=${validCode}&state=${state}&redirect_uri=aroeira://auth/callback`;

      await processOAuthCallback(url, mockCallbacks, mockGetLoadingState);

      expect(mockCallbacks.resetState).not.toHaveBeenCalledWith(
        expect.stringContaining("invalid"),
      );

      expect(invoke).toHaveBeenCalled();

      expect(goto).toHaveBeenCalled();
    });
  });

  describe("redirect_uri parameter stripping", () => {
    it("should strip redirect_uri parameter before sending to backend", async () => {
      const state = createUniqueState("strip_valid");
      setupLocalStorage(state);
      const url = `aroeira://auth/callback?code=${validCode}&state=${state}&redirect_uri=aroeira://auth/callback`;

      await processOAuthCallback(url, mockCallbacks, mockGetLoadingState);

      expect(invoke).toHaveBeenCalledWith("handle_oauth_callback", {
        callback_url: expect.any(String),
      });

      const calls = vi.mocked(invoke).mock.calls;
      const callbackUrlArg = calls[0]?.[1] as { callback_url: string };

      expect(callbackUrlArg.callback_url).not.toContain("redirect_uri");
      expect(callbackUrlArg.callback_url).toContain("code=" + validCode);
      expect(callbackUrlArg.callback_url).toContain("state=" + state);
    });

    it("should strip redirect_uri even when callback is rejected", async () => {
      const state = createUniqueState("strip_rejected");
      setupLocalStorage(state);
      const url = `aroeira://auth/callback?code=${validCode}&state=${state}&redirect_uri=https://evil.com/callback`;

      await processOAuthCallback(url, mockCallbacks, mockGetLoadingState);

      expect(invoke).not.toHaveBeenCalled();
    });

    it("should preserve other parameters when stripping redirect_uri", async () => {
      const state = createUniqueState("preserve_params");
      setupLocalStorage(state);
      const extraParam = "extra_param=value";
      const url = `aroeira://auth/callback?code=${validCode}&state=${state}&redirect_uri=aroeira://auth/callback&${extraParam}`;

      await processOAuthCallback(url, mockCallbacks, mockGetLoadingState);

      expect(invoke).toHaveBeenCalledWith("handle_oauth_callback", {
        callback_url: expect.any(String),
      });

      const calls = vi.mocked(invoke).mock.calls;
      const callbackUrlArg = calls[0]?.[1] as { callback_url: string };

      expect(callbackUrlArg.callback_url).not.toContain("redirect_uri");
      expect(callbackUrlArg.callback_url).toContain("code=" + validCode);
      expect(callbackUrlArg.callback_url).toContain("state=" + state);
      expect(callbackUrlArg.callback_url).toContain(extraParam);
    });
  });
});
