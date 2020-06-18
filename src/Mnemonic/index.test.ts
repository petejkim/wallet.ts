import { Mnemonic } from ".";
import spanishWordList from "./wordlist.es";

describe("generate", () => {
  test("generates mnemonic phrase from entropy", () => {
    const testCases: { [key: string]: string } = {
      "4d3ef17b17a8a7ec7dfe3e112f7a61f6":
        "essay wasp gain consider media wage wave sick bachelor knock observe undo",
      baa076aafddbeb78ea973289feb05383:
        "rival admit primary wing salt round prevent town measure void belt almost",
      "50df9ecd8b1afc4f4afa49563b8b8cdc":
        "express woman recall bike quit chicken cloud empty file sword tobacco rib",
    };

    Object.keys(testCases).forEach((hex) => {
      const entropy = Buffer.from(hex, "hex");
      const phrase = testCases[hex];
      let mnemonic = new Mnemonic(entropy);
      expect(mnemonic).not.toBe(null);
      expect(mnemonic.entropy.toString("hex")).toBe(hex);
      expect(mnemonic.phrase).toBe(phrase);
      expect(mnemonic.words).toEqual(phrase.split(" "));

      // backwards-compatible style
      mnemonic = Mnemonic.generate(entropy);
      expect(mnemonic).not.toBe(null);
      expect(mnemonic.entropy.toString("hex")).toBe(hex);
      expect(mnemonic.phrase).toBe(phrase);
      expect(mnemonic.words).toEqual(phrase.split(" "));
    });
  });

  test("throws an error when an entropy with an invalid length is passed", () => {
    const testCases: string[] = [
      "4d3ef17b17a8a7ec7dfe3e112f7a61",
      "baa076aafddbeb78ea973289feb053",
      "50df9ecd8b1afc4f4afa49563b",
    ];

    testCases.forEach((hex) => {
      const entropy = Buffer.from(hex, "hex");
      expect(() => new Mnemonic(entropy)).toThrowError(/invalid entropy/);
    });
  });

  test("supports custom word list", () => {
    const testCases: { [key: string]: string } = {
      "4d3ef17b17a8a7ec7dfe3e112f7a61f6":
        "engaño veneno fuente césped masivo vecino venta res arbusto latir náusea tráfico",
      baa076aafddbeb78ea973289feb05383:
        "previo acuerdo papel visor puño pronto pantera texto martes vampiro asombro ahorro",
      "50df9ecd8b1afc4f4afa49563b8b8cdc":
        "este volumen pijama atento peñón calidad carta edición fatiga subir tecla portal",
    };

    Object.keys(testCases).forEach((hex) => {
      const entropy = Buffer.from(hex, "hex");
      const phrase = testCases[hex].normalize("NFKD");
      const mnemonic = new Mnemonic(entropy, spanishWordList);
      expect(mnemonic).not.toBe(null);
      expect(mnemonic.entropy.toString("hex")).toBe(hex);
      expect(mnemonic.phrase).toBe(phrase);
      expect(mnemonic.words).toEqual(phrase.split(" "));
    });
  });
});

describe("parse", () => {
  test("parses mnemonic, verifies checksum, and decodes back to entropy", () => {
    const testCases: { [key: string]: string } = {
      "essay wasp gain consider media wage wave sick bachelor knock observe undo":
        "4d3ef17b17a8a7ec7dfe3e112f7a61f6",
      "rival admit primary wing salt round prevent town measure void belt almost":
        "baa076aafddbeb78ea973289feb05383",
      "express woman recall bike quit chicken cloud empty file sword tobacco rib":
        "50df9ecd8b1afc4f4afa49563b8b8cdc",
    };

    Object.keys(testCases).forEach((phrase) => {
      const hex = testCases[phrase];
      const mnemonic = Mnemonic.parse(phrase);
      expect(mnemonic).not.toBe(null);
      expect(mnemonic!.entropy.toString("hex")).toBe(hex);
      expect(mnemonic!.phrase).toBe(phrase);
      expect(mnemonic!.words).toEqual(phrase.split(" "));
    });
  });

  test("returns null when verification fails", () => {
    const testCases: string[] = [
      "essay wasp gain consider media wage wave sick bachelor knock observe",
      "essay wasp gain consider media wage wave sick bachelor knock observe uncle",
      "river admit primary wing salt round prevent town measure void belt almost",
      "express woman recall biology quit chicken cloud empty file sword tobacco rib",
    ];

    testCases.forEach((phrase) => {
      expect(Mnemonic.parse(phrase)).toBe(null);
    });
  });

  test("supports custom word list", () => {
    const testCases: { [key: string]: string } = {
      "engaño veneno fuente césped masivo vecino venta res arbusto latir náusea tráfico":
        "4d3ef17b17a8a7ec7dfe3e112f7a61f6",
      "previo acuerdo papel visor puño pronto pantera texto martes vampiro asombro ahorro":
        "baa076aafddbeb78ea973289feb05383",
      "este volumen pijama atento peñón calidad carta edición fatiga subir tecla portal":
        "50df9ecd8b1afc4f4afa49563b8b8cdc",
    };

    Object.keys(testCases).forEach((phrase) => {
      const normalizedPhrase = phrase.normalize("NFKD");
      const hex = testCases[phrase];
      const mnemonic = Mnemonic.parse(normalizedPhrase, spanishWordList);
      expect(mnemonic).not.toBe(null);
      expect(mnemonic!.entropy.toString("hex")).toBe(hex);
      expect(mnemonic!.phrase).toBe(normalizedPhrase);
      expect(mnemonic!.words).toEqual(normalizedPhrase.split(" "));
    });
  });
});

describe("toSeed", () => {
  test("returns a binary seed derived from a mnemonic phrase", () => {
    const testCases: { [key: string]: string } = {
      "essay wasp gain consider media wage wave sick bachelor knock observe undo":
        "b7df235f1e8addda6befbdf66f4df613474e8ff6041c7826e4df7fa68aa8c244a1d687eda050f97fc20fc2fcd8c09e19ef21d6c14f523639b033e9fc4e6375a6",
      "rival admit primary wing salt round prevent town measure void belt almost":
        "267d6fe81adc779fd2e875d62739cc67690af67025bca8fc6b1f5f3228fb312a1a9b10dedbb3cffc62730438f5afc8725dac6ee11fcd319b98611863226a2957",
      "express woman recall bike quit chicken cloud empty file sword tobacco rib":
        "c35ecec5b1986cd3a1407bc3c829610eb5fc9497e59f31c151a5ce422c7ff7e68bdf3343343605a53db8e7376a932a74b3e08296c0b51476f3d288b750089d9d",
    };

    Object.keys(testCases).forEach((phrase) => {
      const seed = testCases[phrase];
      const mnemonic = Mnemonic.parse(phrase);
      expect(mnemonic!.toSeed().toString("hex")).toBe(seed);
    });
  });
});

describe("toSeedAsync", () => {
  test("returns a binary seed derived from a mnemonic phrase", async () => {
    const testCases: { [key: string]: string } = {
      "essay wasp gain consider media wage wave sick bachelor knock observe undo":
        "b7df235f1e8addda6befbdf66f4df613474e8ff6041c7826e4df7fa68aa8c244a1d687eda050f97fc20fc2fcd8c09e19ef21d6c14f523639b033e9fc4e6375a6",
      "rival admit primary wing salt round prevent town measure void belt almost":
        "267d6fe81adc779fd2e875d62739cc67690af67025bca8fc6b1f5f3228fb312a1a9b10dedbb3cffc62730438f5afc8725dac6ee11fcd319b98611863226a2957",
      "express woman recall bike quit chicken cloud empty file sword tobacco rib":
        "c35ecec5b1986cd3a1407bc3c829610eb5fc9497e59f31c151a5ce422c7ff7e68bdf3343343605a53db8e7376a932a74b3e08296c0b51476f3d288b750089d9d",
    };

    for (const phrase of Object.keys(testCases)) {
      const seed = testCases[phrase];
      const mnemonic = Mnemonic.parse(phrase);
      const derivedSeed = await mnemonic!.toSeedAsync();
      expect(derivedSeed.toString("hex")).toBe(seed);
    }
  });
});
