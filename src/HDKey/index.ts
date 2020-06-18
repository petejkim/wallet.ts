import BN from "bn.js";
import * as bs58 from "bs58";
import * as crypto from "crypto";
import { ec as EC, eddsa as EDDSA } from "elliptic";
import versions, { VersionBytes } from "../versions";

// Implements BIP-32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// Added ED25519 support: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

export enum Algorithm {
  secp256k1 = "secp256k1",
  ed25519 = "ed25519",
}

const SUPPORTED_ALGORITHMS = [Algorithm.secp256k1, Algorithm.ed25519];
const HARDENED_KEY_OFFSET = 0x80000000; // 2^31

const secp256k1 = new EC(Algorithm.secp256k1);
const ed25519 = new EDDSA(Algorithm.ed25519);

export interface HDKeyConstructorOptions {
  algorithm?: Algorithm;
  chainCode: Buffer;
  privateKey?: Buffer | null;
  publicKey?: Buffer | null;
  index?: number;
  depth?: number;
  parentFingerprint?: Buffer;
  version?: VersionBytes;
}

export class HDKey {
  private readonly _algorithm: Algorithm;
  private readonly _privateKey: Buffer | null = null;
  private readonly _publicKey: Buffer;
  private readonly _chainCode: Buffer;
  private readonly _index: number;
  private readonly _depth: number;
  private readonly _parentFingerprint: Buffer;
  private readonly _version: VersionBytes;
  private readonly _keyIdentifier: Buffer;

  constructor({
    algorithm,
    privateKey,
    publicKey,
    chainCode,
    index,
    depth,
    parentFingerprint,
    version,
  }: HDKeyConstructorOptions) {
    if (algorithm && SUPPORTED_ALGORITHMS.indexOf(algorithm) === -1) {
      throw new Error(`unsupported algorithm: ${algorithm}`);
    }
    this._algorithm = algorithm || Algorithm.secp256k1;

    if (!privateKey && !publicKey) {
      throw new Error("either private key or public key must be provided");
    }

    if (privateKey) {
      this._privateKey = privateKey;
      this._publicKey = publicFromPrivateKey(privateKey, this.algorithm);
    } else {
      this._publicKey = publicKey as Buffer;
    }

    this._chainCode = chainCode;
    this._depth = depth || 0;
    this._index = index || 0;
    this._parentFingerprint = parentFingerprint || Buffer.alloc(4);
    this._keyIdentifier = hash160(this._publicKey);
    this._version = version || versions.bitcoinMain;
  }

  public static parseMasterSeed(seed: Buffer, version?: VersionBytes): HDKey {
    return this.parseSeedWithKey(
      Algorithm.secp256k1,
      "Bitcoin seed",
      seed,
      version
    );
  }

  public static parseEd25519Seed(seed: Buffer, version?: VersionBytes): HDKey {
    return this.parseSeedWithKey(
      Algorithm.ed25519,
      "ed25519 seed",
      seed,
      version
    );
  }

  private static parseSeedWithKey(
    algorithm: Algorithm,
    key: string,
    seed: Buffer,
    version?: VersionBytes
  ): HDKey {
    const i = hmacSha512(key, seed);
    const iL = i.slice(0, 32);
    const iR = i.slice(32);
    return new HDKey({ algorithm, privateKey: iL, chainCode: iR, version });
  }

  public static parseExtendedKey(
    key: string,
    version: VersionBytes = versions.bitcoinMain
  ): HDKey {
    // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] ||
    // chain_code[32] || key_data[33] || checksum[4]
    const decoded = Buffer.from(bs58.decode(key));
    if (decoded.length > 112) {
      throw new Error("invalid extended key");
    }

    const checksum = decoded.slice(-4);
    const buf = decoded.slice(0, -4);
    if (!sha256(sha256(buf)).slice(0, 4).equals(checksum)) {
      throw new Error("invalid checksum");
    }

    let o: number = 0;
    const versionRead = buf.readUInt32BE(o);
    o += 4;
    const depth = buf.readUInt8(o);
    o += 1;
    let parentFingerprint: Buffer | undefined = buf.slice(o, (o += 4));
    if (parentFingerprint.readUInt32BE(0) === 0) {
      parentFingerprint = undefined;
    }
    const index = buf.readUInt32BE(o);
    o += 4;
    const chainCode = buf.slice(o, (o += 32));
    const keyData = buf.slice(o);
    const privateKey = keyData[0] === 0 ? keyData.slice(1) : undefined;
    const publicKey = keyData[0] !== 0 ? keyData : undefined;

    if (
      (privateKey && versionRead !== version.bip32.private) ||
      (publicKey && versionRead !== version.bip32.public)
    ) {
      throw new Error("invalid version bytes");
    }

    return new HDKey({
      privateKey,
      publicKey,
      chainCode,
      index,
      depth,
      parentFingerprint,
      version,
    });
  }

  public get algorithm(): Algorithm {
    return this._algorithm;
  }

  public get privateKey(): Buffer | null {
    return this._privateKey || null;
  }

  public get publicKey(): Buffer {
    return this._publicKey;
  }

  public get chainCode(): Buffer {
    return this._chainCode;
  }

  public get depth(): number {
    return this._depth;
  }

  public get parentFingerprint(): Buffer {
    return this._parentFingerprint;
  }

  public get index(): number {
    return this._index;
  }

  public get keyIdentifier(): Buffer {
    return this._keyIdentifier;
  }

  public get fingerprint(): Buffer {
    return this._keyIdentifier.slice(0, 4);
  }

  public get version(): VersionBytes {
    return this._version;
  }

  public get extendedPrivateKey(): string | null {
    if (this.algorithm === Algorithm.ed25519) {
      throw new Error(
        "extended private key generation is not supported for ed25519"
      );
    }
    return this._privateKey
      ? this.serialize(this._version.bip32.private, this._privateKey)
      : null;
  }

  public get extendedPublicKey(): string {
    if (this.algorithm === Algorithm.ed25519) {
      throw new Error(
        "extended public key generation is not supported for ed25519"
      );
    }
    return this.serialize(this._version.bip32.public, this._publicKey);
  }

  public derive(chain: string): HDKey {
    const c = chain.toLowerCase();

    let childKey: HDKey = this;
    c.split("/").forEach((path) => {
      const p = path.trim();
      if (p === "m" || p === "m'" || p === "") {
        return;
      }
      const index = Number.parseInt(p, 10);
      if (Number.isNaN(index)) {
        throw new Error("invalid child key derivation chain");
      }
      const hardened = p.slice(-1) === "'";
      childKey = childKey.deriveChildKey(index, hardened);
    });

    return childKey;
  }

  private deriveChildKey(childIndex: number, hardened: boolean): HDKey {
    if (childIndex >= HARDENED_KEY_OFFSET) {
      throw new Error("invalid index");
    }
    if (!this.privateKey && !this.publicKey) {
      throw new Error("either private key or public key must be provided");
    }

    let index = childIndex;
    const data = Buffer.alloc(37);
    let offset = 0; // offset

    if (hardened) {
      if (!this.privateKey) {
        throw new Error("cannot derive a hardened child key from a public key");
      }
      // 0x00 || ser256(kpar) || ser32(i)
      // 0x00[1] || parent_private_key[32] || child_index[4]
      index += HARDENED_KEY_OFFSET;
      offset += 1;
      offset += this.privateKey.copy(data, offset);
    } else {
      if (this.algorithm === Algorithm.ed25519) {
        throw new Error(
          "non-hardened key generation is not supported for ed25519"
        );
      }
      // serP(point(kpar)) || ser32(i)
      // compressed_parent_public_key[33] || child_index[4]
      offset += this.publicKey.copy(data, offset);
    }
    offset += data.writeUInt32BE(index, offset);

    const i = hmacSha512(this.chainCode, data);
    const iL = new BN(i.slice(0, 32));
    const iR = i.slice(32); // the returned chain code ci is IR

    // ed25519
    if (this.algorithm === Algorithm.ed25519) {
      if (!this.privateKey) {
        throw new Error(
          "derivation from public parent key is not supported for ed25519"
        );
      }

      // if curve is ed25519: The returned child key ki is parse256(IL)
      const childKey = iL;
      return new HDKey({
        algorithm: this.algorithm,
        privateKey: childKey.toArrayLike(Buffer, "be", 32),
        chainCode: iR,
        index,
        depth: this.depth + 1,
        parentFingerprint: this.fingerprint,
        version: this.version,
      });
    }

    // secp256k1
    // if parse256(IL) >= n, the resulting key is invalid; proceed with the next
    // value for i
    if (iL.cmp(secp256k1.n as BN) >= 0) {
      return this.deriveChildKey(childIndex + 1, hardened);
    }

    if (this.privateKey) {
      // child key ki is parse256(IL) + kpar (mod n)
      const childKey = iL.add(new BN(this.privateKey)).mod(secp256k1.n as BN);

      // if ki = 0, the resulting key is invalid; proceed with the next value
      // for i
      if (childKey.cmp(new BN(0)) === 0) {
        return this.deriveChildKey(childIndex + 1, hardened);
      }

      return new HDKey({
        algorithm: this.algorithm,
        privateKey: childKey.toArrayLike(Buffer, "be", 32),
        chainCode: iR,
        index,
        parentFingerprint: this.fingerprint,
        depth: this.depth + 1,
        version: this.version,
      });
    } else {
      // Ki is point(parse256(IL)) + Kpar = G * IL + Kpar
      const parentKey = secp256k1.keyFromPublic(this.publicKey).pub;
      const childKey = secp256k1.g.mul(iL).add(parentKey);

      // if Ki is the point at infinity, the resulting key is invalid; proceed
      // with the next value for i
      if (childKey.isInfinity()) {
        return this.deriveChildKey(childIndex + 1, false);
      }
      const compressedChildKey = Buffer.from(childKey.encode(null, true));

      return new HDKey({
        depth: this.depth + 1,
        publicKey: compressedChildKey,
        chainCode: iR,
        parentFingerprint: this.fingerprint,
        index,
        version: this.version,
      });
    }
  }

  private serialize(version: number, key: Buffer): string {
    // version_bytes[4] || depth[1] || parent_fingerprint[4] || index[4] ||
    // chain_code[32] || key_data[33] || checksum[4]
    const buf = Buffer.alloc(78);
    let o: number = buf.writeUInt32BE(version, 0);
    o = buf.writeUInt8(this.depth, o);
    o += this.parentFingerprint.copy(buf, o);
    o = buf.writeUInt32BE(this.index, o);
    o += this.chainCode.copy(buf, o);
    o += 33 - key.length;
    key.copy(buf, o);
    const checksum = sha256(sha256(buf)).slice(0, 4);
    return bs58.encode(Buffer.concat([buf, checksum]));
  }
}

function hmacSha512(key: Buffer | string, data: Buffer): Buffer {
  return crypto.createHmac("sha512", key).update(data).digest();
}

function sha256(data: Buffer): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

function hash160(data: Buffer): Buffer {
  const d = crypto.createHash("sha256").update(data).digest();
  return crypto.createHash("rmd160").update(d).digest();
}

function publicFromPrivateKey(
  privateKey: Buffer,
  algorithm: Algorithm
): Buffer {
  let publicKey: string;

  switch (algorithm) {
    case Algorithm.secp256k1: {
      publicKey = secp256k1.keyFromPrivate(privateKey).getPublic(true, "hex");
      break;
    }
    case Algorithm.ed25519: {
      publicKey = "00" + ed25519.keyFromSecret(privateKey).getPublic("hex");
      break;
    }
    default:
      throw new Error("unsupported algorithm");
  }

  return Buffer.from(publicKey, "hex");
}
