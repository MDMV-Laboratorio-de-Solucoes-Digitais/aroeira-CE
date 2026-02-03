/// <reference types="@testing-library/jest-dom" />
import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import App from "./App.svelte";

describe("App.svelte", () => {
  it("should render h1", () => {
    render(App);

    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading).toBeInTheDocument();
    expect(heading).toHaveTextContent("App");
  });
});
