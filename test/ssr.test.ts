// @vitest-environment node
import { describe, it, expect } from "vitest";
import { SecurityStorage } from "../src/securityStorage";

describe("SecurityStorage in SSR context (no window/localStorage)", () => {
    it("does not throw when instantiated", () => {
        expect(() => new SecurityStorage("test-secret-key")).not.toThrow();
    });

    it("setItem is a safe no-op", () => {
        const storage = new SecurityStorage("test-secret-key");
        expect(() => storage.setItem("key", "value")).not.toThrow();
    });

    it("getItem returns null", () => {
        const storage = new SecurityStorage("test-secret-key");
        expect(storage.getItem("key")).toBeNull();
    });

    it("removeItem and clear are safe no-ops", () => {
        const storage = new SecurityStorage("test-secret-key");
        expect(() => storage.removeItem("key")).not.toThrow();
        expect(() => storage.clear()).not.toThrow();
    });
});