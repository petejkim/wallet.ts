declare module "elliptic" {
  import BN from "bn.js";

  export class Point {
    x: BN;
    y: BN;
    mul(k: BN): Point;
    add(p: Point): Point;
    isInfinity(): boolean;
    encode(encoding: "hex", compact: boolean): string;
    encode(encoding: null, compact: boolean): number[];
    encode(): number[];
  }

  export class Signature {
    r: BN;
    s: BN;
    recoveryParam: number | null;
  }

  export class ECKeyPair {
    priv: Point;
    pub: Point;
    getPublic(): Point;
    getPublic(encoding: "hex"): string;
    getPublic(compact: boolean, encoding: "hex"): string;
    sign(
      msg: string,
      encoding: "hex",
      options?: { canonical: boolean }
    ): Signature;
    sign(msg: Buffer, options?: { canonical: boolean }): Signature;
  }

  export class EC {
    n: BN;
    g: Point;
    constructor(curve: string);
    keyFromPrivate(priv: string, encoding: "hex"): ECKeyPair;
    keyFromPrivate(priv: Buffer): ECKeyPair;
    keyFromPublic(pub: string, encoding: "hex"): ECKeyPair;
    keyFromPublic(pub: Buffer | BN): ECKeyPair;
    recoverPubKey(
      msg: Buffer,
      signature: { r: Buffer; s: Buffer },
      recoveryParam: number
    ): Point;
  }

  export class EDDSAKeyPair {
    getPublic(encoding: "hex"): string;
  }

  export class EDDSA {
    g: Point;
    constructor(curve: string);
    keyFromSecret(priv: Buffer): EDDSAKeyPair;
    keyFromPublic(pub: Buffer | BN): EDDSAKeyPair;
  }

  export interface PresetCurve {
    n: BN;
    g: Point;
  }

  const curves: {
    secp256k1: PresetCurve;
    ed25519: PresetCurve;
  };

  export { EC as ec, EDDSA as eddsa, curves };
}
