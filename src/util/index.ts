import elliptic, { KeyPair } from 'elliptic'

const secp256k1 = new elliptic.ec('secp256k1')

export function uncompressPublicKey (publicKey: Buffer): Buffer {
  const length = publicKey.length
  const firstByte = publicKey[0]
  if ((length !== 33 && length !== 65) || firstByte < 2 || firstByte > 4) {
    throw new Error('invalid public key')
  }
  let key: KeyPair
  try {
    key = secp256k1.keyFromPublic(publicKey)
  } catch (_err) {
    throw new Error('invalid public key')
  }
  return Buffer.from(key.getPublic().encode())
}

export default {
  uncompressPublicKey
}
