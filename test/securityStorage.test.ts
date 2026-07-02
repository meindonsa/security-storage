import { describe, it, expect, beforeEach, vi } from "vitest";
import { AES, enc, HmacSHA256 } from "crypto-js";
import { compressToUTF16 } from "lz-string";
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

    it("accepts empty string as data", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("emptyVal", "");
        expect(storage.getItem("emptyVal")).toBe("");
    });

    it("accepts falsy values (0, false) as data", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("zero", 0);
        storage.setItem("bool", false);
        expect(storage.getItem("zero")).toBe(0);
        expect(storage.getItem("bool")).toBe(false);
    });

    it("stores data under a namespaced key", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", "value");
        expect(localStorage.getItem("__ss_token")).not.toBeNull();
    });

    it("still reads data written under the legacy non-namespaced key", () => {
        const storage = new SecurityStorage("test-secret-key");
        // Simule une entrée écrite par une version antérieure de la lib (pré-namespacing)
        // en réutilisant directement le mécanisme interne de chiffrement via setItem,
        // puis en déplaçant la donnée vers la clé legacy.
        storage.setItem("legacyStyle", "old-value");
        const namespaced = localStorage.getItem("__ss_legacyStyle");
        localStorage.removeItem("__ss_legacyStyle");
        localStorage.setItem("legacyStyle", namespaced as string);
        expect(storage.getItem("legacyStyle")).toBe("old-value");
    });

    it("clear() only removes keys managed by the library", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", "value");
        localStorage.setItem("unrelated-app-key", "should-survive");

        storage.clear();

        expect(storage.getItem("token")).toBeNull();
        expect(localStorage.getItem("unrelated-app-key")).toBe("should-survive");
    });


    it("stores v2 payloads with random IV and HMAC", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", "value");
        const raw = JSON.parse(localStorage.getItem("__ss_token") as string);
        expect(raw.v).toBe(2);
        expect(raw.d).toHaveProperty("iv");
        expect(raw.d).toHaveProperty("c");
        expect(raw.d).toHaveProperty("h");
    });

    it("uses a different IV for each entry", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("a", "value1");
        storage.setItem("b", "value2");
        const rawA = JSON.parse(localStorage.getItem("__ss_a") as string);
        const rawB = JSON.parse(localStorage.getItem("__ss_b") as string);
        expect(rawA.d.iv).not.toBe(rawB.d.iv);
    });

    it("rejects tampered data (HMAC check)", () => {
        const storage = new SecurityStorage("test-secret-key");
        storage.setItem("token", "value");
        const raw = JSON.parse(localStorage.getItem("__ss_token") as string);
        raw.d.h = "0".repeat(64); // on falsifie le HMAC
        localStorage.setItem("__ss_token", JSON.stringify(raw));
        //expect(() => storage.getItem("token")).toThrow();
        expect(storage.getItem("token")).toBeNull();
    });

    it("still reads legacy v1 data (Phase 0 format, fixed IV, no HMAC)", () => {
        const secretKey = "test-secret-key";
        const constantIv = "8f3e5abe9f0406905fd09f8e8d5b30d8";
        const cipherText = AES.encrypt(JSON.stringify("legacy-value"), secretKey, {
            iv: enc.Hex.parse(constantIv),
        }).toString();
        const compressed = compressToUTF16(cipherText);
        localStorage.setItem("legacyKey", JSON.stringify({ v: 1, d: compressed }));

        const storage = new SecurityStorage(secretKey);
        expect(storage["decryptLegacyFixedIv"](compressed, secretKey)).toBe("legacy-value");
    });

    it("generates and persists a default key when none is provided", () => {
        const storage = new SecurityStorage();
        const generatedKey = localStorage.getItem("_security_storage_default_key");
        expect(generatedKey).not.toBeNull();

        // Une seconde instance sans clé doit réutiliser la même clé par défaut
        storage.setItem("token", "value");
        const storage2 = new SecurityStorage();
        expect(storage2.getItem("token")).toBe("value");
    });

    it("warns when using the auto-generated default key", () => {
        const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
        localStorage.clear();
        new SecurityStorage();
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});