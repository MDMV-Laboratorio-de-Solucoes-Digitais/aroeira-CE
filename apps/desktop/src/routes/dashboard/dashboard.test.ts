import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Mock } from "vitest";
import DashboardPage from "./+page.svelte";
import { invoke } from "@tauri-apps/api/core";
import { goto } from "$app/navigation";
import { resolve } from "$app/paths";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("$app/navigation", () => ({
  goto: vi.fn(),
}));

vi.mock("$app/paths", () => ({
  resolve: (p: string) => p,
}));

describe("Dashboard Page", () => {
  const mockNotes = [
    {
      id: "c704a323-2983-4125-8247-533e2d5c16a1",
      title: "Note 1",
      content: "Content 1",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: "b8d3e6e8-3c6d-4d5e-9b1a-9c2b3a4f5d6e",
      title: "Note 2",
      content: "Content 2",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();

    // Mock invoke with command-specific implementation
    // Backend now handles token storage internally
    (invoke as Mock).mockImplementation((cmd: string) => {
      if (cmd === "get_notes") return Promise.resolve(mockNotes);
      if (cmd === "create_note") return Promise.resolve(null);
      if (cmd === "update_note") return Promise.resolve(null);
      if (cmd === "delete_note") return Promise.resolve(null);
      if (cmd === "logout") return Promise.resolve(null);
      return Promise.resolve(null);
    });
  });

  it("redirects to login if not authenticated", async () => {
    // Mock get_notes to throw an error (simulating auth failure)
    // Backend now returns structured error with AUTH_REQUIRED code
    (invoke as Mock).mockImplementation((cmd: string) => {
      if (cmd === "get_notes")
        return Promise.reject(
          JSON.stringify({
            code: "AUTH_REQUIRED",
            message: "Authentication required",
          }),
        );
      return Promise.resolve(null);
    });

    render(DashboardPage);
    await waitFor(() => {
      expect(goto).toHaveBeenCalledWith(resolve("/login"), {
        replaceState: true,
      });
    });
  });

  it("loads and displays notes", async () => {
    render(DashboardPage);

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("get_notes");
    });

    expect(screen.getByText("Note 1")).toBeInTheDocument();
    expect(screen.getByText("Note 2")).toBeInTheDocument();
  });

  it("filters notes based on search", async () => {
    render(DashboardPage);
    await waitFor(() => expect(screen.getByText("Note 1")).toBeInTheDocument());

    const searchInput = screen.getByPlaceholderText(/search notes\.\.\./i);
    await fireEvent.input(searchInput, { target: { value: "Note 1" } });

    expect(screen.getByText("Note 1")).toBeInTheDocument();
    expect(screen.queryByText("Note 2")).not.toBeInTheDocument();
  });

  it("opens create modal and calls create_note", async () => {
    render(DashboardPage);
    await waitFor(() => expect(screen.getByText("Note 1")).toBeInTheDocument());

    const newNoteBtn = screen.getByRole("button", { name: /new note/i });
    await fireEvent.click(newNoteBtn);

    expect(
      screen.getByRole("heading", { name: /create note/i }),
    ).toBeInTheDocument();

    const titleInput = screen.getByPlaceholderText(
      /enter a descriptive title\.\.\./i,
    );
    const contentInput = screen.getByPlaceholderText(
      /write your thoughts here\.\.\./i,
    );

    await fireEvent.input(titleInput, { target: { value: "New Note Title" } });
    await fireEvent.input(contentInput, { target: { value: "New Content" } });

    const saveBtn = screen.getByRole("button", { name: /save/i });
    await fireEvent.click(saveBtn);

    expect(invoke).toHaveBeenCalledWith("create_note", {
      title: "New Note Title",
      content: "New Content",
    });
  });

  it("calls delete_note when delete confirmed", async () => {
    render(DashboardPage);
    await waitFor(() => expect(screen.getByText("Note 1")).toBeInTheDocument());

    const deleteBtns = screen.getAllByRole("button", { name: /delete/i });
    await fireEvent.click(deleteBtns[0]); // Delete Note 1

    // The confirmation dialog button has visible text "Delete" (not just aria-label)
    const confirmBtn = await screen.findByText(/^delete$/i, {
      selector: "button",
    });
    await fireEvent.click(confirmBtn);

    expect(invoke).toHaveBeenCalledWith("delete_note", {
      id: mockNotes[0].id,
    });
  });
});
