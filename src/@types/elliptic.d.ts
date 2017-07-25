declare module 'elliptic' {
  import BN from 'bn.js'
  import { Buffer } from 'buffer'

  export declare class Point {
    x: BN
    y: BN
    mul (k: BN): Point
    add (p: Point): Point
    isInfinity (): boolean
    encode (encoding: 'hex', compact: boolean): string
    encode (encoding: null, compact: boolean): number[]
    encode (): number[]
  }

  export declare class KeyPair {
    priv: Point
    pub: Point
    getPublic (): Point
  }

  export declare class EC {
    n: BN
    g: Point
    constructor (curve: string)
    keyFromPublic (key: string, encoding: 'hex'): KeyPair
    keyFromPublic (key: Buffer): KeyPair
  }

  export default {
    ec: EC
  }
}
