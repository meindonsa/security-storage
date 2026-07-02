import {AES, enc, lib, mode, pad, HmacSHA256, SHA256} from "crypto-js";
import {compressToUTF16, decompressFromUTF16} from "lz-string";
import {Constant} from "./constant";


interface MetaData {
    _keyStr: string;
    array: { [key: string]: string };
}

export class SecurityStorage {
    private encryptionKey: string;
    private metaStore: MetaData | null = null;

    constructor(secretKey: string | null = null) {
        this.encryptionKey = secretKey ?? this.resolveDefaultKey();
        this.init();
    }

    private init(): void {
        let encrypted: string | null = localStorage.getItem(Constant.keys_name);
        if (encrypted == null) {
            this.metaStore = {
                _keyStr: this.generateRandomKey(),
                array: {},
            };
            this.encryptMetaData(this.metaStore);
        } else {
            if (this.metaStore == null){
                this.metaStore = this.decrypt(encrypted, this.encryptionKey);
            }
        }
    }

    private encryptMetaData(data: MetaData| null): void {
        const encrypted: string = this.encrypt(data, this.encryptionKey);
        localStorage.setItem(Constant.keys_name, encrypted);
    }

    public setItem(key: string, data: any): void {
        if(this.hasInvalidString(key, data)){
            console.error("Opération impossible !");
            return
        }

        if(this.metaStore == null) this.init();
        if(this.metaStore == null) {
            console.error("Impossible d'initialiser le stockage sécurisé.");
            return;
        }

        const newKey: string = this.generateRandomKey();
        const encrypted: string = this.encrypt(data, newKey);
        this.metaStore.array[key] = newKey;
        localStorage.setItem(key, encrypted);
        this.encryptMetaData(this.metaStore);
    }

    public getItem(key: string): any | null {
        if(this.hasInvalidString(key)){
            console.error("Opération impossible !");
            return null;
        }

        if(this.metaStore == null) this.init();

        const encrypted: string | null = localStorage.getItem(key);
        if(encrypted == null) return null;

        const encryptKey: string | undefined = this.metaStore?.array[key];
        if(!encryptKey) return null;

        return this.decrypt(encrypted, encryptKey);
    }

    public removeItem(key: string): void {
        if(this.hasInvalidString(key)){
            console.error("Opération impossible !");
            return;
        }
        if(this.metaStore == null) this.init();
        localStorage.removeItem(key)
        delete this.metaStore?.array[key];
        this.encryptMetaData(this.metaStore);
    }

    public clear(): void {
        localStorage.clear();
        this.init();
    }

    private encrypt(data: any, secretKey: string): string {
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
        } catch (error) {
            console.error("Encryption error:", error);
            throw error;
        }
    }

    private decrypt(encryptedData: string, secretKey: string): any {
        try {
            let parsed: any = null;
            try {
                parsed = JSON.parse(encryptedData);
            } catch {
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
        } catch (error) {
            console.error("Decryption error:", error);
            throw error;
        }
    }

    private decryptLegacyFixedIv(compressed: string, secretKey: string): any {
        const decompressedData = decompressFromUTF16(compressed);
        if (!decompressedData) throw new Error("Decompression failed");
        const originalData = AES.decrypt(decompressedData, secretKey, {
            iv: enc.Hex.parse(Constant.iv),
            keySize: 256 / 32,
            mode: mode.CBC,
            padding: pad.Pkcs7,
        }).toString(enc.Utf8);
        if (!originalData) throw new Error("Decryption failed");
        return JSON.parse(originalData);
    }

    private decryptV2(payload: { iv: string; c: string; h: string }, secretKey: string): any {
        const { encKey, macKey } = this.deriveKeys(secretKey);
        const decompressedData = decompressFromUTF16(payload.c);
        if (!decompressedData) throw new Error("Decompression failed");

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
        if (!originalData) throw new Error("Decryption failed");
        return JSON.parse(originalData);
    }

    private generateRandomKey(length: number = 100): string {
        const randomBytes = lib.WordArray.random(length / 2);
        return enc.Hex.stringify(randomBytes);
    }

    private deriveKeys(secretKey: string): { encKey: string; macKey: string } {
        const encKey = SHA256(secretKey + ":enc").toString(enc.Hex);
        const macKey = SHA256(secretKey + ":mac").toString(enc.Hex);
        return { encKey, macKey };
    }

    private resolveDefaultKey(): string {
        if (typeof localStorage === "undefined") {
            throw new Error(
                "SecurityStorage: no secretKey provided and localStorage is unavailable to generate a default one."
            );
        }

        let key = localStorage.getItem(Constant.default_key_name);
        if (!key) {
            key = this.generateRandomKey();
            localStorage.setItem(Constant.default_key_name, key);
            console.warn(
                "SecurityStorage: no secretKey provided. A random per-browser key was generated automatically. " +
                "This offers basic protection only (not secure against XSS or on a shared/public device). " +
                "For production apps handling sensitive data, pass an explicit secretKey."
            );
        }
        return key;
    }

    private hasInvalidString(...strings: (string | null | undefined)[]): boolean {
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