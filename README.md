wallet.ts
=========

[![npm version](https://badge.fury.io/js/wallet.ts.svg)](https://www.npmjs.com/package/wallet.ts)
[![Downloads](https://img.shields.io/npm/dm/wallet.ts.svg)](https://www.npmjs.com/package/wallet.ts)

A collection of utilities for building cryptocurrency wallets, written in TypeScript.

## BIP 32 - Hierarchical Deterministic Wallets [(Spec)](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

```typescript
const { HDKey } = require('wallet.ts')

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
const { Mnemonic } = require('wallet.ts')

const mnemonic = Mnemonic.generate(randomBytes(32))
const phrase: string = mnemonic.phrase
const words: string[] = mnemonic.words
const seed: Buffer = mnemonic.toSeed()
```

## Ethereum Address / EIP 55 checksum

```typescript
const { EthereumAddress } = require('wallet.ts')

const publicKey = Buffer.from(
  '028a8c59fa27d1e0f1643081ff80c3cf0392902acbf76ab0dc9c414b8d115b0ab3',
  'hex'
)
const address: string = EthereumAddress.from(publicKey)
// => 0xD11A13f484E2f2bD22d93c3C3131f61c05E876a
const valid: boolean = EthereumAddress.isValid(address)
// => true
const checksumAddress: string = EthereumAddress.checksumAddress(
  '0xd11a13f484e2f2bd22d93c3c3131f61c05e876a'
)
// => 0xD11A13f484E2f2bD22d93c3C3131f61c05E876a
```

- - -
Copyright © 2017 Peter Jihoon Kim. This project is licensed under the [ISC license](https://raw.githubusercontent.com/petejkim/wallet.ts/master/LICENSE).
