import {AES, enc, lib, mode, pad} from "crypto-js";
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
        this.encryptionKey = secretKey ?? Constant.base_key;
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
            const encryptedData = AES.encrypt(JSON.stringify(data), secretKey, {
                iv: enc.Hex.parse(Constant.iv),
                keySize: 256 / 32,
                mode: mode.CBC,
                padding: pad.Pkcs7,
            }).toString();
            const compressed = compressToUTF16(encryptedData);
            return JSON.stringify({ v: Constant.schema_version, d: compressed });
        } catch (error) {
            console.error("Encryption error:", error);
            throw error;
        }
    }

    private decrypt(encryptedData: string, secretKey: string): any {
        try {
            let compressed: string = encryptedData;
            try {
                const parsed = JSON.parse(encryptedData);
                if (parsed && typeof parsed === "object" && "v" in parsed && "d" in parsed) {
                    compressed = parsed.d;
                }
            } catch {
                // Format hérité (avant versionnement) : encryptedData est directement la chaîne compressée
            }
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
        } catch (error) {
            console.error("Decryption error:", error);
            throw error;
        }
    }

    private generateRandomKey(length: number = 100): string {
        const randomBytes = lib.WordArray.random(length / 2);
        return enc.Hex.stringify(randomBytes);
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