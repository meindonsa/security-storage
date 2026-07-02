# @security-storage

SECURE-STORAGE is a lite library that purpose is to encrypt your data and store it in localStorage.

####

Library use `Crypto-js` to encrypt you data, `Lz-string` to compress data encrypted and save it in localStorage with native JavaScript `localStorage`

## Requirements

- [Crypto-js](https://www.npmjs.com/package/crypto-js)
- [LZ-String](https://www.npmjs.com/package/lz-string)

## Installation

```bash
npm install meindonsa/security-storage --save
```

## Usage

#### Import service in your service or component

```typescript
import SecurityStorage from "@meindonsa/security-storage";
...

securityStorage = new SecurityStorage(/* your custom encryption key recommended */);
```

then, you can use differents methods of service:

- set

`setItem` encrypts your data and saves it in specified key and in localStorage. If the key is not provided, the library will warn. Following types of JavaScript objects are supported: `Array`, `Blob`,`Float`,`Number`, `Object` ,`String`

| Parameter               | Description                        |
| :---------------------- | :--------------------------------- |
| `key`                   | key to store data in localStorage  |
| `data`                  | data to store                      |

###

- get

`getItem` gets data back from specified key from the localStorage library. If the key is not provided, the library will warn.

| Parameter               | Description                        |
| :---------------------- | :--------------------------------- |
| `key`                   | key to get data from localStorage  |

###

- remove

`removeItem` removes the value of a key from the localStorage.

| Parameter | Description                                          |
| :-------- | :--------------------------------------------------- |
| `key`     | key to identify data and remove it from localStorage |

###

- clean

`clean` remove all your data from the localStorage, this method don't take parameter

### Example

eg :

```typescript

import SecurityStorage from "@meindonsa/security-storage";
...

securityStorage = new SecurityStorage(/*your ecryption key or not */);

setItem() {
    this.securityStorage.set(key, data);
}

getItem() {
    return this.securityStorage.get(key);
}

removeItem() {
    this.securityStorage.remove(key);
}

clear() {
    this.securityStorage.clean();
}

```

## SSR / Server-Side Rendering

La librairie détecte automatiquement l'absence de `window`/`localStorage` (Angular Universal, Next.js, etc.)
et devient un no-op sûr côté serveur : aucune exception levée, `getItem` renvoie `null`,
les autres méthodes ne font rien tant que le code s'exécute côté serveur.

## Clear

`clear()` ne supprime que les entrées gérées par cette instance de `SecurityStorage`
(plus ses métadonnées internes), pas l'intégralité du `localStorage` du domaine.
## Authors

## Dérivation de clé

Depuis la version 3 du schéma interne, les clés de chiffrement et d'intégrité (HMAC) sont
dérivées de la `secretKey` fournie via PBKDF2 plutôt qu'un simple hachage, ce qui renforce
la résistance contre une clé faible. Les données déjà stockées avec les versions
précédentes du schéma restent lisibles automatiquement (migration transparente à la
prochaine écriture).

- [@Meindonsa](https://github.com/Meindonsa)

## Support

For support, email borisaxel1998@gmail.com
