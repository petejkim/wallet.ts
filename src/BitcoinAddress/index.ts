import versions, { VersionBytes } from "../versions";

import bs58 from "bs58";
import crypto from "crypto";

export interface BitcoinAddressConstructorOptions {
  publicKey: Buffer;
  version?: VersionBytes;
}

export default class BitcoinAddress {
  private _publicKey: Buffer;
  private _rawAddress?: Buffer;
  private _address?: string;
  private _version: VersionBytes;

  private constructor({
    publicKey,
    version,
  }: BitcoinAddressConstructorOptions) {
    const length = publicKey.length;
    const firstByte = publicKey[0];
    if ((length !== 33 && length !== 65) || firstByte < 2 || firstByte > 4) {
      throw new Error("invalid public key");
    }
    this._publicKey = publicKey;
    this._version = version || versions.bitcoinMain;
  }

  static from(publicKey: Buffer, version?: VersionBytes): BitcoinAddress {
    return new BitcoinAddress({ publicKey, version });
  }

  static isValid(_address: string): boolean {
    if (_address.length < 26 || _address.length > 35) {
      return false;
    }

    let rawAddress: Buffer;
    try {
      rawAddress = Buffer.from(bs58.decode(_address));
    } catch (_err) {
      return false;
    }

    const checksumFromAddress = rawAddress.slice(-4);
    const checksum = sha256(sha256(rawAddress.slice(0, -4))).slice(0, 4);

    return checksum.equals(checksumFromAddress);
  }

  get publicKey(): Buffer {
    return this._publicKey;
  }

  get rawAddress(): Buffer {
    if (!this._rawAddress) {
      const hash = hash160(this._publicKey);
      const prefixedHash = Buffer.alloc(1 + hash.length);
      prefixedHash.writeUInt8(this._version.public, 0);
      hash.copy(prefixedHash, 1);
      const checksum = sha256(sha256(prefixedHash)).slice(0, 4);
      this._rawAddress = Buffer.concat([prefixedHash, checksum]);
    }
    return this._rawAddress;
  }

  get address(): string {
    if (!this._address) {
      this._address = bs58.encode(this.rawAddress);
    }
    return this._address;
  }
}

function sha256(data: Buffer): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

function hash160(data: Buffer): Buffer {
  const d = crypto.createHash("sha256").update(data).digest();
  return crypto.createHash("rmd160").update(d).digest();
}
