import { lib, enc, AES, pad, mode, HmacSHA256, SHA256 } from 'crypto-js';
import { compressToUTF16, decompressFromUTF16 } from 'lz-string';

const Constant = {
    keys_name: "_security_storage_meta_data",
    //base_key: "3b)w4&T£wy9$U4-PVSw]0moP!x7+g(",
    default_key_name: "_security_storage_default_key",
    iv: "8f3e5abe9f0406905fd09f8e8d5b30d8",
    schema_version: 2,
};

class SecurityStorage {
    constructor(secretKey = null) {
        this.metaStore = null;
        if (!this.isStorageAvailable()) {
            this.encryptionKey = secretKey !== null && secretKey !== void 0 ? secretKey : "";
            this.metaStore = null;
            return;
        }
        this.encryptionKey = secretKey !== null && secretKey !== void 0 ? secretKey : this.resolveDefaultKey();
        this.init();
    }
    isStorageAvailable() {
        return typeof window !== "undefined" && typeof localStorage !== "undefined";
    }
    namespacedKey(key) {
        return `__ss_${key}`;
    }
    init() {
        let encrypted = localStorage.getItem(Constant.keys_name);
        if (encrypted == null) {
            this.metaStore = {
                _keyStr: this.generateRandomKey(),
                array: {},
            };
            this.encryptMetaData(this.metaStore);
        }
        else {
            if (this.metaStore == null) {
                this.metaStore = this.decrypt(encrypted, this.encryptionKey);
            }
        }
    }
    encryptMetaData(data) {
        const encrypted = this.encrypt(data, this.encryptionKey);
        localStorage.setItem(Constant.keys_name, encrypted);
    }
    setItem(key, data) {
        if (!this.isStorageAvailable())
            return;
        if (this.isInvalidKey(key) || this.isInvalidData(data)) {
            console.error("Opération impossible !");
            return;
        }
        if (this.metaStore == null)
            this.init();
        if (this.metaStore == null) {
            console.error("Impossible d'initialiser le stockage sécurisé.");
            return;
        }
        try {
            const newKey = this.generateRandomKey();
            const encrypted = this.encrypt(data, newKey);
            this.metaStore.array[key] = newKey;
            localStorage.setItem(this.namespacedKey(key), encrypted);
            this.encryptMetaData(this.metaStore);
        }
        catch (error) {
            console.error("SecurityStorage.setItem failed:", error);
        }
    }
    getItem(key) {
        var _a;
        if (!this.isStorageAvailable())
            return null;
        if (this.isInvalidKey(key)) {
            console.error("Invalid operation !");
            return null;
        }
        if (this.metaStore == null)
            this.init();
        let encrypted = localStorage.getItem(this.namespacedKey(key));
        if (encrypted == null) {
            encrypted = localStorage.getItem(key);
        }
        if (encrypted == null)
            return null;
        const encryptKey = (_a = this.metaStore) === null || _a === void 0 ? void 0 : _a.array[key];
        if (!encryptKey)
            return null;
        try {
            return this.decrypt(encrypted, encryptKey);
        }
        catch (error) {
            console.error("SecurityStorage.getItem failed:", error);
            return null;
        }
    }
    removeItem(key) {
        var _a;
        if (!this.isStorageAvailable())
            return;
        if (this.isInvalidKey(key)) {
            console.error("Opération impossible !");
            return;
        }
        if (this.metaStore == null)
            this.init();
        localStorage.removeItem(this.namespacedKey(key));
        localStorage.removeItem(key);
        (_a = this.metaStore) === null || _a === void 0 ? true : delete _a.array[key];
        this.encryptMetaData(this.metaStore);
    }
    clear() {
        if (!this.isStorageAvailable())
            return;
        if (this.metaStore) {
            Object.keys(this.metaStore.array).forEach((key) => {
                localStorage.removeItem(this.namespacedKey(key));
                localStorage.removeItem(key); // compat clés legacy non préfixées
            });
        }
        localStorage.removeItem(Constant.keys_name);
        this.metaStore = null;
        this.init();
    }
    encrypt(data, secretKey) {
        try {
            const { encKey, macKey } = this.deriveKeys(secretKey);
            const ivWords = lib.WordArray.random(16);
            const ivHex = enc.Hex.stringify(ivWords);
            const cipherText = AES.encrypt(JSON.stringify(data), encKey, {
                iv: ivWords,
                keySize: 256 / 32,
                mode: mode.CBC,
                padding: pad.Pkcs7,
            }).toString();
            const hmac = HmacSHA256(cipherText, macKey).toString(enc.Hex);
            const compressed = compressToUTF16(cipherText);
            return JSON.stringify({
                v: Constant.schema_version,
                d: { iv: ivHex, c: compressed, h: hmac },
            });
        }
        catch (error) {
            console.error("Encryption error:", error);
            throw error;
        }
    }
    decrypt(encryptedData, secretKey) {
        try {
            let parsed = null;
            try {
                parsed = JSON.parse(encryptedData);
            }
            catch (_a) {
                parsed = null;
            }
            // Format legacy v0 (avant Phase 0) : chaîne compressée brute, pas de wrapper {v, d}
            if (parsed === null || typeof parsed !== "object" || !("v" in parsed) || !("d" in parsed)) {
                return this.decryptLegacyFixedIv(encryptedData, secretKey);
            }
            // Format v1 (Phase 0) : wrapper {v:1, d: compressed}, IV fixe, pas de HMAC
            if (parsed.v === 1) {
                return this.decryptLegacyFixedIv(parsed.d, secretKey);
            }
            // Format v2 (Phase 1) : IV aléatoire + HMAC
            if (parsed.v === 2) {
                return this.decryptV2(parsed.d, secretKey);
            }
            throw new Error(`Unsupported schema version: ${parsed.v}`);
        }
        catch (error) {
            console.error("Decryption error:", error);
            throw error;
        }
    }
    decryptLegacyFixedIv(compressed, secretKey) {
        const decompressedData = decompressFromUTF16(compressed);
        if (!decompressedData)
            throw new Error("Decompression failed");
        const originalData = AES.decrypt(decompressedData, secretKey, {
            iv: enc.Hex.parse(Constant.iv),
            keySize: 256 / 32,
            mode: mode.CBC,
            padding: pad.Pkcs7,
        }).toString(enc.Utf8);
        if (!originalData)
            throw new Error("Decryption failed");
        return JSON.parse(originalData);
    }
    decryptV2(payload, secretKey) {
        const { encKey, macKey } = this.deriveKeys(secretKey);
        const decompressedData = decompressFromUTF16(payload.c);
        if (!decompressedData)
            throw new Error("Decompression failed");
        const expectedHmac = HmacSHA256(decompressedData, macKey).toString(enc.Hex);
        if (expectedHmac !== payload.h) {
            throw new Error("Integrity check failed: data may have been tampered with");
        }
        const originalData = AES.decrypt(decompressedData, encKey, {
            iv: enc.Hex.parse(payload.iv),
            keySize: 256 / 32,
            mode: mode.CBC,
            padding: pad.Pkcs7,
        }).toString(enc.Utf8);
        if (!originalData)
            throw new Error("Decryption failed");
        return JSON.parse(originalData);
    }
    generateRandomKey(length = 100) {
        const randomBytes = lib.WordArray.random(length / 2);
        return enc.Hex.stringify(randomBytes);
    }
    deriveKeys(secretKey) {
        const encKey = SHA256(secretKey + ":enc").toString(enc.Hex);
        const macKey = SHA256(secretKey + ":mac").toString(enc.Hex);
        return { encKey, macKey };
    }
    resolveDefaultKey() {
        if (typeof localStorage === "undefined") {
            throw new Error("SecurityStorage: no secretKey provided and localStorage is unavailable to generate a default one.");
        }
        let key = localStorage.getItem(Constant.default_key_name);
        if (!key) {
            key = this.generateRandomKey();
            localStorage.setItem(Constant.default_key_name, key);
            console.warn("SecurityStorage: no secretKey provided. A random per-browser key was generated automatically. " +
                "This offers basic protection only (not secure against XSS or on a shared/public device). " +
                "For production apps handling sensitive data, pass an explicit secretKey.");
        }
        return key;
    }
    isInvalidKey(key) {
        return key === null || key === undefined || key === '';
    }
    isInvalidData(data) {
        return data === undefined;
    }
}

export { SecurityStorage };
//# sourceMappingURL=securityStorage.esm.js.map
