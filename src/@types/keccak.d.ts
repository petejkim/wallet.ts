declare module 'keccak/js' {
  class Keccak {
    update (data: Buffer): Keccak
    update (data: string, encoding: string): Keccak
    digest (): Buffer
    digest (encoding: string): string
  }

  export default function createKeccakHash (
    algorithm:
      | 'keccak224'
      | 'keccak256'
      | 'keccak384'
      | 'keccak512'
      | 'sha3-224'
      | 'sha3-256'
      | 'sha3-384'
      | 'sha3-512'
  ): Keccak
}
