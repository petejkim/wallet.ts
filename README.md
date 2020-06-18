# wallet.ts

[![npm version](https://badge.fury.io/js/wallet.ts.svg)](https://www.npmjs.com/package/wallet.ts)
[![Downloads](https://img.shields.io/npm/dm/wallet.ts.svg)](https://www.npmjs.com/package/wallet.ts)
![CI](https://github.com/petejkim/wallet.ts/workflows/CI/badge.svg)

A collection of utilities for building cryptocurrency wallets, written in
TypeScript. Requires Node.js 12.0.0+.

## Hierarchical Deterministic Wallets [(BIP 32)](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

```javascript
const { randomBytes } = require("crypto");
const { HDKey } = require("wallet.ts");

const seed = randomBytes(66);

const masterKey = HDKey.parseMasterSeed(seed);
// => HDKey {...}

const extendedPrivateKey = masterKey.derive("m/44'/60'/0'/0")
  .extendedPrivateKey;
// => "xprvA2FBfTJAyLjF5..."

const childKey = HDKey.parseExtendedKey(extendedPrivateKey);
// => HDKey {...}

const wallet = childKey.derive("0");
// => HDKey {...}

const walletPrivateKey = wallet.privateKey;
// => <Buffer 44 04 ce 4a ...>

const walletPublicKey = wallet.publicKey;
// => <Buffer 03 e9 f6 10 ...>
```

[View Source](https://github.com/petejkim/wallet.ts/blob/master/src/HDKey/index.ts)

## Mnemonic code for generating deterministic keys [(BIP 39)](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

```javascript
const { randomBytes } = require("crypto");
const { Mnemonic } = require("wallet.ts");

const mnemonic = Mnemonic.generate(randomBytes(32));
// => Mnemonic {...}

const phrase = mnemonic.phrase;
// => "capital find public couple ..."

const words = mnemonic.words;
// => [ "capital", "find", "public", "couple", ...]

const seed = mnemonic.toSeed();
// => <Buffer cd 07 60 43 ...>
```

[View Source](https://github.com/petejkim/wallet.ts/blob/master/src/Mnemonic/index.ts)

## Ethereum Address / EIP 55 checksum

```javascript
const { EthereumAddress } = require("wallet.ts");

const publicKey = Buffer.from(
  "028a8c59fa27d1e0f1643081ff80c3cf0392902acbf76ab0dc9c414b8d115b0ab3",
  "hex"
);

const address = EthereumAddress.from(publicKey).address;
// => "0xD11A13f484E2f2bD22d93c3C3131f61c05E876a9"

const valid = EthereumAddress.isValid(address);
// => true

const checksumAddress = EthereumAddress.checksumAddress(
  "0xd11a13f484e2f2bd22d93c3c3131f61c05e876a9"
);
// => "0xD11A13f484E2f2bD22d93c3C3131f61c05E876a9"
```

[View Source](https://github.com/petejkim/wallet.ts/blob/master/src/EthereumAddress/index.ts)

## Bitcoin Address (deprecated)

```javascript
const { BitcoinAddress } = require("wallet.ts");

const publicKey = Buffer.from(
  "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
  "hex"
);

const address = BitcoinAddress.from(publicKey).address;
// => "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"

const valid = BitcoinAddress.isValid(address);
// => true
```

[View Source](https://github.com/petejkim/wallet.ts/blob/master/src/BitcoinAddress/index.ts)

---

Copyright © 2018-2020 Coinbase, Inc.

Copyright © 2017-2018 HardFork Inc.

This project is licensed under the
[ISC license](https://raw.githubusercontent.com/petejkim/wallet.ts/master/LICENSE).
