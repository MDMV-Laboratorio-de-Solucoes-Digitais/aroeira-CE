import { describe, it, expect } from "vitest";
import { cn } from "./utils";

describe("utils", () => {
  describe("cn", () => {
    it("merges class names correctly", () => {
      expect(cn("c1", "c2")).toBe("c1 c2");
    });

    it("handles conditional classes", () => {
      const isTrue = true;
      const isFalse = false;
      expect(cn("c1", isTrue && "c2", isFalse && "c3")).toBe("c1 c2");
    });

    it("merges tailwind classes", () => {
      expect(cn("p-4", "p-2")).toBe("p-2");
      expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500");
    });

    it("handles mix of arrays and strings", () => {
      expect(cn(["c1", "c2"], "c3")).toBe("c1 c2 c3");
    });
  });
});
