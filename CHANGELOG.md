# Changelog

## [2.0.0](https://github.com/meindonsa/security-storage/compare/0.3.18...2.0.0) (2026-07-02)

### ⚠ BREAKING CHANGES

* SecurityStorage constructor now requires a non-empty secretKey.
The previous hardcoded default key has been removed.

- encrypt/decrypt now use a random IV per entry (schema v2)
- key derivation splits encKey/macKey via SHA256(secretKey + context)
- HMAC-SHA256 verifies ciphertext integrity before decryption
- legacy v0 (pre-versioning) and v1 (Phase 0) formats remain readable

### Features

* Generate latest version ([91e5d24](https://github.com/meindonsa/security-storage/commit/91e5d2474d73af5235948c66148e39efc5b32ff1))
* PBKDF2 key derivation (schema v3), remove stray commented secret ([1f888b1](https://github.com/meindonsa/security-storage/commit/1f888b17b49dc9500111dfd580f8f1da9a7caf60))
* random IV per entry + mandatory secretKey + HMAC integrity check ([152390f](https://github.com/meindonsa/security-storage/commit/152390fbc0471af11302157a57cfb6f6ccff29c4))
* Remove console.log and update Readme ([47de87b](https://github.com/meindonsa/security-storage/commit/47de87b8f77aff46ba6f24902d18f70edb013abe))
* SSR safety, scoped clear(), key namespacing, robust error handling ([6396bda](https://github.com/meindonsa/security-storage/commit/6396bda89fd5c6f165f8c213b099bb3afda5210c))

### Bug Fixes

* add schema version wrapper for encrypted payloads (backward-compatible) ([dc431c0](https://github.com/meindonsa/security-storage/commit/dc431c0c012fb382c86b94204f94ced8e2979791))
* Disable puplishing changelog ([3eacfb1](https://github.com/meindonsa/security-storage/commit/3eacfb16e679654d6f967991769604f60dbe74b6))
* Fixed vulnérabilities ([a89ee7e](https://github.com/meindonsa/security-storage/commit/a89ee7e2e39ad99f43cddf2e075217425483d6a4))

## [0.3.18](https://github.com/Meindonsa/security-storage/compare/0.0.2...0.3.0) (2025-03-29)

### ⚠ BREAKING CHANGES

* Improve environment

### Features

* Fixed indexing issue ([312f91e](https://github.com/Meindonsa/security-storage/commit/312f91e5467b57e1c2c8da491d631be17dc7ecf1))
* Improve environment ([701ad0f](https://github.com/Meindonsa/security-storage/commit/701ad0f480f6f8bdd770b3015ab2c776cccebee6))
## [0.3.0](https://github.com/Meindonsa/security-storage/compare/0.0.2...0.3.0) (2025-01-30)

### Features

* Improve library ([e22acd3](https://github.com/Meindonsa/security-storage/commit/e22acd397e4c8713c087cacfcec046064a25e449))
* push 0.3.0 code ([31da098](https://github.com/Meindonsa/security-storage/commit/31da098445e453ca2094d45d6cadf2c05e5e92aa))

### Bug Fixes

* Remove '..gitignore' copy ([b846fb7](https://github.com/Meindonsa/security-storage/commit/b846fb7a959004ad52e1ade80b4ca2e757a83ab3))
* Remove 'thread-loader' from dependances ([dbf15e5](https://github.com/Meindonsa/security-storage/commit/dbf15e5904d2581f67b1b47182d00fe4006e1ed9))

## [0.3.0](https://github.com/Meindonsa/security-storage/compare/0.2.0...0.0.2) (2025-01-30)

### Features

* Improve library ([e22acd3](https://github.com/Meindonsa/security-storage/commit/e22acd397e4c8713c087cacfcec046064a25e449))
* push 0.3.0 code ([31da098](https://github.com/Meindonsa/security-storage/commit/31da098445e453ca2094d45d6cadf2c05e5e92aa))

### Bug Fixes

* Remove '..gitignore' copy ([b846fb7](https://github.com/Meindonsa/security-storage/commit/b846fb7a959004ad52e1ade80b4ca2e757a83ab3))
* Remove 'thread-loader' from dependances ([dbf15e5](https://github.com/Meindonsa/security-storage/commit/dbf15e5904d2581f67b1b47182d00fe4006e1ed9))
## [0.0.2](https://github.com/Meindonsa/security-storage/compare/0.2.0...0.0.2) (2024-11-18)

### Bug Fixes

* Push 0.0.2 version ([5f1f759](https://github.com/Meindonsa/security-storage/commit/5f1f7595fc3d1737474175db197088afff782464))

## [0.0.2](https://github.com/Meindonsa/security-storage/compare/0.2.0...0.0.2) (2024-11-18)

### Bug Fixes

* Push 0.0.2 version ([5f1f759](https://github.com/Meindonsa/security-storage/commit/5f1f7595fc3d1737474175db197088afff782464))

## 0.2.0 (2024-11-18)

### Features

* Add and configure release-it ([dac9525](https://github.com/Meindonsa/security-storage/commit/dac9525b83b9007b49e5a3c47fc4b8aafdda9a4c))
* Add config to publish ([4b7194c](https://github.com/Meindonsa/security-storage/commit/4b7194cc42678b6e9df1d7f83225075e5b6b8e32))
* Add readme file ([009b958](https://github.com/Meindonsa/security-storage/commit/009b958c245baf15792ac5e4b4b416ee55e56d9d))
* Check null data and key befor any treatment ([b6e834c](https://github.com/Meindonsa/security-storage/commit/b6e834c3fcdcfcb476eccaf88510e622421e1bbf))
* create constant file ([db836a6](https://github.com/Meindonsa/security-storage/commit/db836a6cfe87c2f7c01be72aba0e95f0c2be3e8c))
* Encrypt and decrypt data ([b36b380](https://github.com/Meindonsa/security-storage/commit/b36b380340c0898bac5e3d10def2d71fadf930d9))
* Encrypt and save data ([93e43e3](https://github.com/Meindonsa/security-storage/commit/93e43e336fdcb6052c48d6403f941a64d15be962))
* encrypt data ([204fa8f](https://github.com/Meindonsa/security-storage/commit/204fa8f5188f5f4cb444685f93115eddb5d03bfe))
* First commit ([d2e3507](https://github.com/Meindonsa/security-storage/commit/d2e3507d80e8fc059ebcb5e13008d9613d2369d4))
* Generate 0.1.0 lib version ([7ef694b](https://github.com/Meindonsa/security-storage/commit/7ef694b7c78b7a5e00d85e6f87df3e6efe357727))
* Install Crypto-js ([4acc1ba](https://github.com/Meindonsa/security-storage/commit/4acc1babc91cb912675089f56656e353f5341730))
* Install Lz-string ([7ef9e72](https://github.com/Meindonsa/security-storage/commit/7ef9e7259e84423a3cd68a594ef5224e7399a25c))

### Bug Fixes

* Remove dist ([5dc503d](https://github.com/Meindonsa/security-storage/commit/5dc503df76e1e452af8d306ff22a64d420259b49))
* Update Readme file ([6473464](https://github.com/Meindonsa/security-storage/commit/6473464426f102d85c10a635240553330287f0dd))
