import { render, screen, waitFor } from "@testing-library/svelte";
import VerifyPage from "./+page.svelte";
import { vi, describe, it, expect, beforeEach, type Mock } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { goto } from "$app/navigation";
import * as stores from "$app/stores";

// Mock $app/stores
vi.mock("$app/stores", () => {
  return {
    page: {
      subscribe: vi.fn(),
    },
  };
});

import { type Subscriber } from "svelte/store";

// Helper to set page store
function setPageUrl(urlStr: string) {
  const url = new URL(urlStr);
  const mockPage = { url };
  (stores.page.subscribe as unknown as Mock).mockImplementation(
    (run: Subscriber<unknown>) => {
      run(mockPage);
      return () => {};
    },
  );
}

describe("Verify Page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("shows error if token is missing", async () => {
    setPageUrl("http://localhost/verify");
    render(VerifyPage);

    await waitFor(() => {
      expect(
        screen.getByText(/Verification token is missing/i),
      ).toBeInTheDocument();
    });

    expect(invoke).not.toHaveBeenCalled();
  });

  it("calls verify_email invoke when token is present", async () => {
    setPageUrl("http://localhost/verify?token=valid-token-123");
    (invoke as unknown as Mock).mockResolvedValueOnce(null);

    render(VerifyPage);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("verify_email", {
        token: "valid-token-123",
      });
    });

    // Should show success message
    await waitFor(() => {
      expect(screen.getByText(/Account Verified!/i)).toBeInTheDocument();
    });
  });

  it("redirects to login after success", async () => {
    vi.useFakeTimers();
    setPageUrl("http://localhost/verify?token=valid-token-123");
    (invoke as unknown as Mock).mockResolvedValueOnce(null);

    render(VerifyPage);

    await waitFor(() => {
      expect(screen.getByText(/Account Verified!/i)).toBeInTheDocument();
    });

    vi.advanceTimersByTime(4000);

    await waitFor(() => {
      expect(goto).toHaveBeenCalledWith("/login");
    });
  });

  it("shows error if verification fails", async () => {
    setPageUrl("http://localhost/verify?token=invalid-token");
    (invoke as unknown as Mock).mockRejectedValueOnce(
      new Error("Invalid token"),
    );

    render(VerifyPage);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(screen.getByText(/Invalid token/i)).toBeInTheDocument();
    });
  });
});
