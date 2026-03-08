import { expect, test } from "@playwright/test";

test.describe("Authentication Flow", () => {
  test.beforeEach(async ({ page }) => {
    // Mock Tauri invoke mechanism
    await page.addInitScript(() => {
      // Mock for Tauri v2
      const w = globalThis as any;

      // Initialize if undefined
      w.__TAURI_INTERNALS__ = w.__TAURI_INTERNALS__ || {};

      w.__TAURI_INTERNALS__.invoke = async (
        cmd: string,
        args?: Record<string, unknown>,
      ) => {
        // Sanitize logging to remove sensitive arguments
        console.log(`[Tauri Mock] invoke: ${cmd}`);

        switch (cmd) {
          case "get_password_policy":
            return { level: "secure", min_length: 8 };

          case "has_auth_token":
            return false; // Default to not logged in

          case "login":
            if (
              args &&
              args.email === "test@example.com" &&
              args.password === "password123"
            ) {
              return null; // Success
            }
            throw new Error("Invalid credentials");

          case "register":
            if (args && args.email === "new@example.com") {
              return null; // Success
            }
            throw new Error("Registration failed");

          case "get_notes":
            return []; // Return empty notes list

          case "logout":
            return null; // Success

          default:
            console.warn(`[Tauri Mock] Unhandled command: ${cmd}`);
            throw new Error(`Command ${cmd} not mocked`);
        }
      };

      // Some versions of Tauri api might look for this or use the internals directly
      w.__TAURI__ = {
        core: {
          invoke: w.__TAURI_INTERNALS__.invoke,
        },
      };
    });
  });

  test("should handle login failure", async ({ page }) => {
    await page.goto("/login"); // Should redirect here anyway

    await page.getByLabel("Email").fill("wrong@example.com");
    await page.getByLabel("Password").fill("wrongpass");
    await page.getByRole("button", { name: /sign in/i }).click();

    // Verify error message
    // Note: The app displays a generic error message for security on failure or specific one?
    // In code: handleError returns "Authentication failed..."
    const alert = page.getByRole("alert");
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("Authentication");
  });

  test("should handle successful login", async ({ page }) => {
    await page.goto("/login");

    await page.getByLabel("Email").fill("test@example.com");
    await page.getByLabel("Password").fill("password123");
    await page.getByRole("button", { name: /sign in/i }).click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByRole("heading", { name: /dashboard/i })).toBeVisible(
      { timeout: 10000 },
    );
  });

  test("should verify logout flow", async ({ page }) => {
    await page.goto("/login");

    await page.getByLabel("Email").fill("test@example.com");
    await page.getByLabel("Password").fill("password123");
    await page.getByRole("button", { name: /sign in/i }).click();

    // Wait for dashboard
    await expect(page).toHaveURL(/\/dashboard/);

    // Click logout
    await page.getByRole("button", { name: /logout/i }).click();

    // Should verify redirect to login
    await expect(
      page.getByRole("heading", { name: /welcome back/i }),
    ).toBeVisible();
  });

  test("should validate password mismatch in register", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: /create an account/i }).click();

    await page.getByLabel("Email").fill("new@example.com");
    await page.getByLabel("Password", { exact: true }).fill("Pass123!");
    await page.getByLabel("Confirm Password").fill("Mismatch123!");
    await page.getByRole("button", { name: /create account/i }).click();

    // Should show error for mismatch (Client side check in +page.svelte)
    const alert = page.getByRole("alert");
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("Passwords do not match");
  });

  test("should handle client-side resilience (network/invoke failure)", async ({
    page,
  }) => {
    // Override mock to simulate failure
    await page.addInitScript(() => {
      const w = globalThis as any;
      // Initialize if undefined
      w.__TAURI_INTERNALS__ = w.__TAURI_INTERNALS__ || {};

      w.__TAURI_INTERNALS__.invoke = async (cmd: string) => {
        if (cmd === "get_password_policy")
          return { level: "secure", min_length: 8 };
        throw new Error("Network Error");
      };

      // Keep the public API in sync with internals
      w.__TAURI__ = w.__TAURI__ || { core: { invoke: async () => null } };
      w.__TAURI__.core.invoke = w.__TAURI_INTERNALS__.invoke;
    });

    await page.goto("/login");
    await page.getByLabel("Email").fill("test@example.com");
    await page.getByLabel("Password").fill("password123");
    await page.getByRole("button", { name: /sign in/i }).click();

    const alert = page.getByRole("alert");
    await expect(alert).toBeVisible();
    // It should not crash, just show error
  });
});
