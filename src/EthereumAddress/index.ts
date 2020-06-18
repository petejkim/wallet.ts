import createKeccakHash from "keccak";
import { decompressPublicKey, strip0x } from "../util";

export class EthereumAddress {
  private _publicKey: Buffer;
  private _rawAddress?: Buffer;
  private _address?: string;

  private constructor(publicKey: Buffer) {
    this._publicKey = decompressPublicKey(publicKey);
  }

  public static from(publicKey: Buffer): EthereumAddress {
    return new EthereumAddress(publicKey);
  }

  public static checksumAddress(address: string): string {
    if (!isValidFormat(address)) {
      throw new Error("invalid address");
    }

    const addr = strip0x(address).toLowerCase();
    const hash = createKeccakHash("keccak256")
      .update(addr, "ascii")
      .digest("hex");
    let newAddr: string = "0x";

    for (let i = 0; i < addr.length; i++) {
      if (hash[i] >= "8") {
        newAddr += addr[i].toUpperCase();
      } else {
        newAddr += addr[i];
      }
    }

    return newAddr;
  }

  public static isValid(address: string): boolean {
    if (!isValidFormat(address)) {
      return false;
    }

    const addr = strip0x(address);
    if (addr.match(/[0-9a-f]{40}/) || addr.match(/[0-9A-F]{40}/)) {
      return true;
    }

    let checksumAddress: string;
    try {
      checksumAddress = EthereumAddress.checksumAddress(addr);
    } catch (_err) {
      return false;
    }

    return addr === checksumAddress.slice(2);
  }

  public get publicKey(): Buffer {
    return this._publicKey;
  }

  public get rawAddress(): Buffer {
    if (!this._rawAddress) {
      this._rawAddress = createKeccakHash("keccak256")
        .update(this._publicKey.slice(1))
        .digest()
        .slice(-20);
    }
    return this._rawAddress;
  }

  public get address(): string {
    if (!this._address) {
      const rawAddress = this.rawAddress.toString("hex");
      this._address = EthereumAddress.checksumAddress(rawAddress);
    }
    return this._address;
  }
}

function isValidFormat(address: string): boolean {
  return !!strip0x(address).match(/^[0-9a-fA-F]{40}$/);
}
