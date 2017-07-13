wallet.ts
=========

[![npm version](https://badge.fury.io/js/wallet.ts.svg)](https://www.npmjs.com/package/wallet.ts)
[![Downloads](https://img.shields.io/npm/dm/wallet.ts.svg)](https://www.npmjs.com/package/wallet.ts)

A collection of utilities for building cryptocurrency wallets, written in TypeScript.

## BIP 32 - Hierarchical Deterministic Wallets [(Spec)](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

```typescript
const { HDKey } = require('wallet.ts').bip32

const seed = Buffer.from(
  '3474351f920e66add91d9fcb62da911bea1a01872f10648601eb18d51b63cfd2782c5b29c3e9d219d6a83e9957512d7e16c0c6f69557c88cca43014d9d1abed2',
  'hex'
)
const masterKey: HDKey = HDKey.parseMasterSeed(seed)
const extendedPrivateKey: string = masterKey.derive("m/44'/60'/0'/0").extendedPrivateKey
const childKey: HDKey = HDKey.parseExtendedKey(extendedPrivateKey)
const wallet: HDKey = childKey.derive('0')
const walletPrivateKey: Buffer = wallet.privateKey
const walletPublicKey: Buffer = wallet.publicKey
```

## BIP 39 - Mnemonic code for generating deterministic keys [(Spec)](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

```typescript
const { randomBytes } = require('crypto')
const { Mnemonic } = require('wallet.ts').bip39

const mnemonic = Mnemonic.generate(randomBytes(32))
const phrase: string = mnemonic.phrase
const words: string[] = mnemonic.words
const seed: Buffer = mnemonic.toSeed()
```

- - -
Copyright © 2017 Peter Jihoon Kim. This project is licensed under the [ISC license](https://raw.githubusercontent.com/petejkim/wallet.ts/master/LICENSE).
