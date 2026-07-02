import { describe, it, expect, beforeEach, vi } from "vitest";
import { SecurityStorage } from "../src/securityStorage";

describe("SecurityStorage", () => {
    beforeEach(() => {
        localStorage.clear();
    });

    it("stores and retrieves a value", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", { hello: "world" });
        expect(storage.getItem("token")).toEqual({ hello: "world" });
    });

    it("returns null for a missing key", () => {
        const storage = new SecurityStorage("test-secret-key");
        expect(storage.getItem("nope")).toBeNull();
    });

    it("removes a value", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", "value");
        storage.removeItem("token");
        expect(storage.getItem("token")).toBeNull();
    });

    it("rejects empty key on setItem", () => {
        const storage = new SecurityStorage("test-secret-key");
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        storage.setItem("", "value");
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });

    it("wraps encrypted payload with schema version", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", "value");
        const raw = localStorage.getItem("token");
        expect(raw).not.toBeNull();
        const parsed = JSON.parse(raw as string);
        expect(parsed).toHaveProperty("v", 1);
        expect(parsed).toHaveProperty("d");
    });
});