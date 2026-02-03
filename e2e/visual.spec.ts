import { test, expect } from "@playwright/test";

test.describe("Visual Regression", () => {
  test("login page snapshot", async ({ page }) => {
    await page.goto("/login");
    // Wait for the form to be visible
    await expect(
      page.getByRole("heading", { name: /welcome back/i }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot("login-page.png", {
      maxDiffPixelRatio: 0.05,
    });
  });

  test("register page snapshot", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: /create an account/i }).click();
    // Wait for the form to be visible
    await expect(
      page.getByRole("heading", { name: /create account/i }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot("register-page.png", {
      maxDiffPixelRatio: 0.05,
    });
  });
});
