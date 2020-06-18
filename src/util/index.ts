import { ec as EC, ECKeyPair } from "elliptic";

const secp256k1 = new EC("secp256k1");

export function decompressPublicKey(publicKey: Buffer): Buffer {
  const length = publicKey.length;
  const firstByte = publicKey[0];
  if ((length !== 33 && length !== 65) || firstByte < 2 || firstByte > 4) {
    throw new Error("invalid public key");
  }
  let key: ECKeyPair;
  try {
    key = secp256k1.keyFromPublic(publicKey);
  } catch (_err) {
    throw new Error("invalid public key");
  }
  return Buffer.from(key.getPublic().encode());
}

export function strip0x(hex: string): string {
  return hex.replace(/^0x/i, "");
}

export function prepend0x(hex: string): string {
  return hex.replace(/^(0x)?/i, "0x");
}

export default { decompressPublicKey, strip0x };
