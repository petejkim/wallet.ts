declare module 'bn.js' {
  import { Buffer } from 'buffer'

  type Endian = 'le' | 'be'

  type ArrayLike = {
    new (size: number): ArrayLike
  }

  declare class BN {
    constructor (
      value: string | number | Buffer | BN,
      base?: number,
      endian?: Endian
    )
    toArrayLike<T> (
      ArrayLike: { new (size: number): T },
      endian?: Endian,
      length?: number
    ): T
    add (b: BN): BN
    mod (b: BN): BN
    cmp (b: BN): number
  }

  export default BN
}
