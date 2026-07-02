'use strict';

var cryptoJs = require('crypto-js');
var lzString = require('lz-string');

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
        this.encryptionKey = secretKey !== null && secretKey !== void 0 ? secretKey : this.resolveDefaultKey();
        this.init();
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
        if (this.hasInvalidString(key, data)) {
            console.error("Opération impossible !");
            return;
        }
        if (this.metaStore == null)
            this.init();
        if (this.metaStore == null) {
            console.error("Impossible d'initialiser le stockage sécurisé.");
            return;
        }
        const newKey = this.generateRandomKey();
        const encrypted = this.encrypt(data, newKey);
        this.metaStore.array[key] = newKey;
        localStorage.setItem(key, encrypted);
        this.encryptMetaData(this.metaStore);
    }
    getItem(key) {
        var _a;
        if (this.hasInvalidString(key)) {
            console.error("Opération impossible !");
            return null;
        }
        if (this.metaStore == null)
            this.init();
        const encrypted = localStorage.getItem(key);
        if (encrypted == null)
            return null;
        const encryptKey = (_a = this.metaStore) === null || _a === void 0 ? void 0 : _a.array[key];
        if (!encryptKey)
            return null;
        return this.decrypt(encrypted, encryptKey);
    }
    removeItem(key) {
        var _a;
        if (this.hasInvalidString(key)) {
            console.error("Opération impossible !");
            return;
        }
        if (this.metaStore == null)
            this.init();
        localStorage.removeItem(key);
        (_a = this.metaStore) === null || _a === void 0 ? true : delete _a.array[key];
        this.encryptMetaData(this.metaStore);
    }
    clear() {
        localStorage.clear();
        this.init();
    }
    encrypt(data, secretKey) {
        try {
            const { encKey, macKey } = this.deriveKeys(secretKey);
            const ivWords = cryptoJs.lib.WordArray.random(16);
            const ivHex = cryptoJs.enc.Hex.stringify(ivWords);
            const cipherText = cryptoJs.AES.encrypt(JSON.stringify(data), encKey, {
                iv: ivWords,
                keySize: 256 / 32,
                mode: cryptoJs.mode.CBC,
                padding: cryptoJs.pad.Pkcs7,
            }).toString();
            const hmac = cryptoJs.HmacSHA256(cipherText, macKey).toString(cryptoJs.enc.Hex);
            const compressed = lzString.compressToUTF16(cipherText);
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
        const decompressedData = lzString.decompressFromUTF16(compressed);
        if (!decompressedData)
            throw new Error("Decompression failed");
        const originalData = cryptoJs.AES.decrypt(decompressedData, secretKey, {
            iv: cryptoJs.enc.Hex.parse(Constant.iv),
            keySize: 256 / 32,
            mode: cryptoJs.mode.CBC,
            padding: cryptoJs.pad.Pkcs7,
        }).toString(cryptoJs.enc.Utf8);
        if (!originalData)
            throw new Error("Decryption failed");
        return JSON.parse(originalData);
    }
    decryptV2(payload, secretKey) {
        const { encKey, macKey } = this.deriveKeys(secretKey);
        const decompressedData = lzString.decompressFromUTF16(payload.c);
        if (!decompressedData)
            throw new Error("Decompression failed");
        const expectedHmac = cryptoJs.HmacSHA256(decompressedData, macKey).toString(cryptoJs.enc.Hex);
        if (expectedHmac !== payload.h) {
            throw new Error("Integrity check failed: data may have been tampered with");
        }
        const originalData = cryptoJs.AES.decrypt(decompressedData, encKey, {
            iv: cryptoJs.enc.Hex.parse(payload.iv),
            keySize: 256 / 32,
            mode: cryptoJs.mode.CBC,
            padding: cryptoJs.pad.Pkcs7,
        }).toString(cryptoJs.enc.Utf8);
        if (!originalData)
            throw new Error("Decryption failed");
        return JSON.parse(originalData);
    }
    generateRandomKey(length = 100) {
        const randomBytes = cryptoJs.lib.WordArray.random(length / 2);
        return cryptoJs.enc.Hex.stringify(randomBytes);
    }
    deriveKeys(secretKey) {
        const encKey = cryptoJs.SHA256(secretKey + ":enc").toString(cryptoJs.enc.Hex);
        const macKey = cryptoJs.SHA256(secretKey + ":mac").toString(cryptoJs.enc.Hex);
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
    hasInvalidString(...strings) {
        if (strings === null || strings === undefined) {
            return true;
        }
        for (const string of strings) {
            if (string === null || string === undefined || string === '') {
                return true;
            }
        }
        return false;
    }
}

exports.SecurityStorage = SecurityStorage;
//# sourceMappingURL=securityStorage.cjs.js.map
