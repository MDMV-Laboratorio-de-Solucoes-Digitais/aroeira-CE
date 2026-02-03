import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { resolve } from "$app/paths";
import type { Mock } from "vitest";
import LoginPage from "./+page.svelte";
import { invoke } from "@tauri-apps/api/core";
import { goto } from "$app/navigation";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("$app/navigation", () => ({
  goto: vi.fn(),
}));

vi.mock("$app/paths", () => ({
  resolve: (p: string) => p,
}));

describe("Login Page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders login form by default", () => {
    render(LoginPage);
    expect(
      screen.getByRole("heading", { name: /welcome back/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(
      screen.queryByLabelText(/confirm password/i),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /sign in/i }),
    ).toBeInTheDocument();
  });

  it("switches to register form", async () => {
    render(LoginPage);
    const toggleBtn = screen.getByRole("button", {
      name: /create an account/i,
    });
    await fireEvent.click(toggleBtn);

    expect(
      screen.getByRole("heading", { name: /create account/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /create account/i }),
    ).toBeInTheDocument();
  });

  it("calls login invoke on submit", async () => {
    (invoke as Mock).mockImplementation((cmd) => {
      if (cmd === "get_password_policy")
        return Promise.resolve({ level: "secure", min_length: 8 });
      if (cmd === "login") return Promise.resolve(undefined);
      return Promise.resolve(undefined);
    });

    render(LoginPage);
    const emailInput = screen.getByLabelText(/email/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitBtn = screen.getByRole("button", { name: /sign in/i });

    await fireEvent.input(emailInput, {
      target: { value: "test@example.com" },
    });
    await fireEvent.input(passwordInput, { target: { value: "password123" } });
    await fireEvent.click(submitBtn);

    expect(invoke).toHaveBeenCalledWith("login", {
      email: "test@example.com",
      password: "password123",
    });
    await waitFor(() => {
      expect(goto).toHaveBeenCalledWith(resolve("/dashboard"), {
        replaceState: true,
      });
    });
  });

  it("displays error message on login failure", async () => {
    (invoke as Mock).mockImplementation((cmd) => {
      if (cmd === "get_password_policy")
        return Promise.resolve({ level: "secure", min_length: 8 });
      if (cmd === "login")
        return Promise.reject(new Error("Invalid credentials"));
      return Promise.resolve(undefined);
    });

    render(LoginPage);

    await fireEvent.input(screen.getByLabelText(/email/i), {
      target: { value: "wrong@example.com" },
    });
    await fireEvent.input(screen.getByLabelText(/password/i), {
      target: { value: "wrong" },
    });
    await fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      const alert = screen.getByRole("alert");
      expect(alert).toBeInTheDocument();
      expect(alert).toHaveTextContent("Authentication failed");
    });
  });
});
