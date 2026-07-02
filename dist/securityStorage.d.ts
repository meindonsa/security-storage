export declare class SecurityStorage {
    private encryptionKey;
    private metaStore;
    private derivedKeysCache;
    constructor(secretKey?: string | null);
    private isStorageAvailable;
    private namespacedKey;
    private init;
    private encryptMetaData;
    setItem(key: string, data: any): void;
    getItem(key: string): any | null;
    removeItem(key: string): void;
    clear(): void;
    private encrypt;
    private decrypt;
    private decryptLegacyFixedIv;
    private decryptV2;
    private decryptV3;
    private generateRandomKey;
    private deriveKeysLegacyV2;
    /** Dérivation courante (Phase 3). PBKDF2 renforce la résistance au brute-force
          *  si secretKey est une valeur faible/devinable. Mis en cache par secretKey pour
          *  éviter de repayer le coût du KDF à chaque appel. */
    private deriveKeysV3;
    private resolveDefaultKey;
    private isInvalidKey;
    private isInvalidData;
}
