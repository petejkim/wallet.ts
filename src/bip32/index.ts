import crypto from 'crypto'
import bs58 from 'bs58'
import versions, { VersionBytes } from './versions'
import BN from 'bn.js'
import elliptic from 'elliptic'

const HARDENED_KEY_OFFSET = 0x80000000
const secp256k1 = new elliptic.ec('secp256k1')

export interface HDKeyConstructorOptions {
  chainCode: Buffer
  privateKey?: Buffer | null
  publicKey?: Buffer | null
  index?: number
  depth?: number
  parentFingerprint?: Buffer
  version?: VersionBytes
}

export class HDKey {
  private _version: VersionBytes
  private _privateKey?: Buffer
  private _publicKey: Buffer
  private _chainCode: Buffer
  private _index: number
  private _depth: number
  private _parentFingerprint?: Buffer
  private _keyIdentifier: Buffer

  constructor ({
    privateKey,
    publicKey,
    chainCode,
    index,
    depth,
    parentFingerprint,
    version
  }: HDKeyConstructorOptions) {
    if (!privateKey && !publicKey) {
      throw new Error('either private key or public key must be provided')
    }
    if (privateKey) {
      this._privateKey = privateKey
      const ecdh = crypto.createECDH('secp256k1')
      ecdh.setPrivateKey(privateKey)
      this._publicKey = Buffer.from(
        ecdh.getPublicKey('latin1', 'compressed'),
        'latin1'
      )
    } else if (publicKey) {
      this._publicKey = publicKey
    }
    this._chainCode = chainCode
    this._depth = depth || 0
    this._index = index || 0
    this._parentFingerprint = parentFingerprint
    this._keyIdentifier = hash160(this._publicKey)
    this._version = version || versions.bitcoinMain
  }

  static parseMasterSeed (seed: Buffer, version?: VersionBytes): HDKey {
    const i = hmacSha512('Bitcoin seed', seed)
    const iL = i.slice(0, 32)
    const iR = i.slice(32)
    return new HDKey({ privateKey: iL, chainCode: iR, version })
  }

  static parseExtendedKey (
    key: string,
    version: VersionBytes = versions.bitcoinMain
  ): HDKey {
    // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] || chain_code[32] || key_data[33] || checksum[4]
    const decoded = new Buffer(bs58.decode(key))
    if (decoded.length > 112) {
      throw new Error('invalid extended key')
    }

    const checksum = decoded.slice(-4)
    const buf = decoded.slice(0, -4)
    if (!sha256(sha256(buf)).slice(0, 4).equals(checksum)) {
      throw new Error('invalid checksum')
    }

    let o: number = 0
    const versionRead = buf.readUInt32BE(o)
    o += 4
    const depth = buf.readUInt8(o)
    o += 1
    let parentFingerprint: Buffer | undefined = buf.slice(o, (o += 4))
    if (parentFingerprint.readUInt32BE(0) === 0) {
      parentFingerprint = undefined
    }
    const index = buf.readUInt32BE(o)
    o += 4
    const chainCode = buf.slice(o, (o += 32))
    const keyData = buf.slice(o)
    const privateKey = keyData[0] === 0 ? keyData.slice(1) : undefined
    const publicKey = keyData[0] !== 0 ? keyData : undefined

    if (
      (privateKey && versionRead !== version.private) ||
      (publicKey && versionRead !== version.public)
    ) {
      throw new Error('invalid version bytes')
    }

    return new HDKey({
      privateKey,
      publicKey,
      chainCode,
      index,
      depth,
      parentFingerprint,
      version
    })
  }

  get privateKey (): Buffer | null {
    return this._privateKey || null
  }

  get publicKey (): Buffer {
    return this._publicKey
  }

  get chainCode (): Buffer {
    return this._chainCode
  }

  get depth (): number {
    return this._depth
  }

  get parentFingerprint (): Buffer | null {
    return this._parentFingerprint || null
  }

  get index (): number {
    return this._index
  }

  get keyIdentifier (): Buffer {
    return this._keyIdentifier
  }

  get fingerprint (): Buffer {
    return this._keyIdentifier.slice(0, 4)
  }

  get version (): VersionBytes {
    return this._version
  }

  get extendedPrivateKey (): string | null {
    return this._privateKey
      ? this.serialize(this._version.private, this._privateKey)
      : null
  }

  get extendedPublicKey (): string {
    return this.serialize(this._version.public, this._publicKey)
  }

  derive (chain: string): HDKey {
    const c = chain.toLowerCase()

    let childKey: HDKey = this
    c.split('/').forEach(path => {
      const p = path.trim()
      if (p === 'm' || p === "m'" || p === '') {
        return
      }
      const index = Number.parseInt(p, 10)
      if (Number.isNaN(index)) {
        throw new Error('invalid child key derivation chain')
      }
      const hardened = p.slice(-1) === "'"
      childKey = childKey.deriveChildKey(index, hardened)
    })

    return childKey
  }

  private deriveChildKey (childIndex: number, hardened: boolean): HDKey {
    if (childIndex >= HARDENED_KEY_OFFSET) {
      throw new Error('invalid index')
    }
    if (!this.privateKey && !this.publicKey) {
      throw new Error('either private key or public key must be provided')
    }

    let index: number = childIndex
    const data: Buffer = new Buffer(37)
    let o: number = 0
    if (hardened) {
      if (!this.privateKey) {
        throw new Error('cannot derive a hardened child key from a public key')
      }
      // 0x00 || ser256(kpar) || ser32(i)
      // 0x00[1] || parent_private_key[32] || child_index[4]
      index += HARDENED_KEY_OFFSET
      o += 1
      o += this.privateKey.copy(data, o)
    } else {
      // serP(point(kpar)) || ser32(i)
      // compressed_parent_public_key[33] || child_index[4]
      o += this.publicKey.copy(data, o)
    }
    o += data.writeUInt32BE(index, o)

    const i = hmacSha512(this.chainCode, data)
    const iL = new BN(i.slice(0, 32))
    const iR = i.slice(32)

    // if parse256(IL) >= n, the resulting key is invalid; proceed with the next value for i
    if (iL.cmp(secp256k1.n) >= 0) {
      return this.deriveChildKey(childIndex + 1, hardened)
    }

    if (this.privateKey) {
      // ki is parse256(IL) + kpar (mod n)
      const childKey = iL.add(new BN(this.privateKey)).mod(secp256k1.n)

      // if ki = 0, the resulting key is invalid; proceed with the next value for i
      if (childKey.cmp(new BN(0)) === 0) {
        return this.deriveChildKey(childIndex + 1, hardened)
      }

      return new HDKey({
        depth: this.depth + 1,
        privateKey: childKey.toArrayLike(Buffer, 'be', 32),
        chainCode: iR,
        parentFingerprint: this.fingerprint,
        index,
        version: this.version
      })
    } else {
      // Ki is point(parse256(IL)) + Kpar = G * IL + Kpar
      const parentKey = secp256k1.keyFromPublic(this.publicKey).pub
      const childKey = secp256k1.g.mul(iL).add(parentKey)

      // if Ki is the point at infinity, the resulting key is invalid; proceed with the next value for i
      if (childKey.isInfinity()) {
        return this.deriveChildKey(childIndex + 1, false)
      }
      const compressedChildKey = new Buffer(childKey.encode(null, true))

      return new HDKey({
        depth: this.depth + 1,
        publicKey: compressedChildKey,
        chainCode: iR,
        parentFingerprint: this.fingerprint,
        index,
        version: this.version
      })
    }
  }

  private serialize (version: number, key: Buffer): string {
    // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] || chain_code[32] || key_data[33] || checksum[4]
    const buf = new Buffer(78)
    let o: number = buf.writeUInt32BE(version, 0)
    o = buf.writeUInt8(this.depth, o)
    o += this.parentFingerprint ? this.parentFingerprint.copy(buf, o) : 4
    o = buf.writeUInt32BE(this.index, o)
    o += this.chainCode.copy(buf, o)
    o += 33 - key.length
    key.copy(buf, o)
    const checksum = sha256(sha256(buf)).slice(0, 4)
    return bs58.encode(Buffer.concat([buf, checksum]))
  }
}

function hmacSha512 (key: Buffer | string, data: Buffer): Buffer {
  return crypto.createHmac('sha512', key).update(data).digest()
}

function sha256 (data: Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest()
}

function hash160 (data: Buffer): Buffer {
  const d = crypto.createHash('sha256').update(data).digest()
  return crypto.createHash('rmd160').update(d).digest()
}
