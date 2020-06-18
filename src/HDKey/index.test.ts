import { HDKey } from ".";

describe("parseMasterSeed", () => {
  test("initialize an instance of HDKey from master seed", () => {
    const seed = Buffer.from(
      "b7df235f1e8addda6befbdf66f4df613474e8ff6041c7826e4df7fa68aa8c244a1d687eda050f97fc20fc2fcd8c09e19ef21d6c14f523639b033e9fc4e6375a6",
      "hex"
    );
    const hdkey = HDKey.parseMasterSeed(seed);
    expect(hdkey.privateKey!.toString("hex")).toBe(
      "ae4ae84fd731b25809815c22f5de48ef4b769484b4a2d2ae5c47f622fbda8e9f"
    );
    expect(hdkey.publicKey.toString("hex")).toBe(
      "02f8205ad1bb6e9680bd920c9ae4ccd51a2a6f466b330bbe6792a831ae2c50a6d3"
    );
    expect(hdkey.depth).toBe(0);
    expect(hdkey.index).toBe(0);
    expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");
  });
});

describe("parseExtendedKey", () => {
  test("initialize an instance of HDKey from an extended private key", () => {
    const hdkey = HDKey.parseExtendedKey(
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    );

    expect(hdkey.depth).toBe(0);
    expect(hdkey.index).toBe(0);
    expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");

    expect(hdkey.publicKey.toString("hex")).toBe(
      "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    );
    expect(hdkey.privateKey!.toString("hex")).toBe(
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    );

    expect(hdkey.extendedPublicKey).toBe(
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );
    expect(hdkey.extendedPrivateKey).toBe(
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    );
  });

  test("initialize an instance of HDKey from an extended public key", () => {
    const hdkey = HDKey.parseExtendedKey(
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );

    expect(hdkey.depth).toBe(0);
    expect(hdkey.index).toBe(0);
    expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");

    expect(hdkey.publicKey.toString("hex")).toBe(
      "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    );
    expect(hdkey.privateKey).toBe(null);

    expect(hdkey.extendedPublicKey).toBe(
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );
    expect(hdkey.extendedPrivateKey).toBe(null);
  });

  test("initialize an instance of HDKey from a derived key", () => {
    const hdkey = HDKey.parseExtendedKey(
      "xprv9uHRZZhbkedL7ChPMJeZbg3bP5LUqJsrpZ393GbdKnoNwZ4dVuA8mv9ZgAoi53z4Uq9EMgtVKFswXRjgiViKUbCnQ2K7uDVbKgCubQjqfDg"
    );
    expect(hdkey.depth).toBe(1);
    expect(hdkey.index).toBe(2);
    expect(hdkey.parentFingerprint!.toString("hex")).toBe("3442193e");

    expect(hdkey.publicKey.toString("hex")).toBe(
      "02fd648f85194d8cad102d63aa29bf86336ed148134eb521c59436500c15588fff"
    );
    expect(hdkey.privateKey!.toString("hex")).toBe(
      "271614f2ca446df6e17e3ea92dacc70a0b6360bf831648a42508e7918a71db8a"
    );
    expect(hdkey.extendedPublicKey).toBe(
      "xpub68Gmy5EVb2BdKgmrTLBZxozKw7AyEmbiBmxjqf1Et8LMpMPn3SUPKiU3XTTrgkJzWbuF8h8E4Ah1m4bWsVqaPa3fzD6p7qEWrFTrgRR1iAe"
    );
    expect(hdkey.extendedPrivateKey).toBe(
      "xprv9uHRZZhbkedL7ChPMJeZbg3bP5LUqJsrpZ393GbdKnoNwZ4dVuA8mv9ZgAoi53z4Uq9EMgtVKFswXRjgiViKUbCnQ2K7uDVbKgCubQjqfDg"
    );
  });
});

describe("derive (secp256k1)", () => {
  describe("test vector 1", () => {
    const seed = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
    const hdkey = HDKey.parseMasterSeed(seed);

    test("chain m", () => {
      expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");
      expect(hdkey.chainCode.toString("hex")).toBe(
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
      );
      expect(hdkey.privateKey!.toString("hex")).toBe(
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
      );
      expect(hdkey.publicKey.toString("hex")).toBe(
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
      );
      expect(hdkey.extendedPublicKey).toBe(
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
      );
      expect(hdkey.extendedPrivateKey).toBe(
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
      );

      const derived = hdkey.derive("m");
      expect(hdkey.chainCode).toBe(derived.chainCode);
      expect(hdkey.privateKey).toBe(derived.privateKey);
      expect(hdkey.publicKey).toBe(derived.publicKey);
      expect(hdkey.extendedPublicKey).toBe(derived.extendedPublicKey);
      expect(hdkey.extendedPrivateKey).toBe(derived.extendedPrivateKey);
    });

    test("chain m/0'", () => {
      const child = hdkey.derive("m/0'");
      expect(child.parentFingerprint!.toString("hex")).toBe("3442193e");
      expect(child.chainCode.toString("hex")).toBe(
        "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
      );
    });

    test("chain m/0'/1", () => {
      const child = hdkey.derive("m/0'/1");
      expect(child.parentFingerprint!.toString("hex")).toBe("5c1bd648");
      expect(child.chainCode.toString("hex")).toBe(
        "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
      );
    });

    test("chain m/0'/1/2'", () => {
      const child = hdkey.derive("m/0'/1/2'");
      expect(child.parentFingerprint!.toString("hex")).toBe("bef5a2f9");
      expect(child.chainCode.toString("hex")).toBe(
        "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
      );
    });

    test("chain m/1'/1/2'/2", () => {
      const child = hdkey.derive("m/0'/1/2'/2");
      expect(child.parentFingerprint!.toString("hex")).toBe("ee7ab90c");
      expect(child.chainCode.toString("hex")).toBe(
        "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
      );
    });

    test("chain m/1'/1/2'/2/1000000000", () => {
      const child = hdkey.derive("m/0'/1/2'/2/1000000000");
      expect(child.parentFingerprint!.toString("hex")).toBe("d880d7d8");
      expect(child.chainCode.toString("hex")).toBe(
        "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
      );
    });

    test("derive key from a derived key", () => {
      const child = hdkey.derive("m/0'").derive("m/1");
      expect(child.extendedPublicKey).toBe(
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
      );
    });

    test("public parent key -> hardened child key", () => {
      const parent = HDKey.parseExtendedKey(hdkey.extendedPublicKey);
      expect(() => {
        parent.derive("m/0'");
      }).toThrow(/hardened/);
    });

    test("public parent key -> non-hardened child key", () => {
      const parent = HDKey.parseExtendedKey(hdkey.extendedPublicKey);
      const child = parent.derive("m/0");
      expect(child.extendedPublicKey).toBe(
        "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"
      );
      expect(child.extendedPrivateKey).toBe(null);
    });
  });

  describe("test vector 2", () => {
    const seed = Buffer.from(
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      "hex"
    );
    const hdkey = HDKey.parseMasterSeed(seed);

    test("chain m", () => {
      expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");
      expect(hdkey.chainCode.toString("hex")).toBe(
        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
      );
      expect(hdkey.privateKey!.toString("hex")).toBe(
        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
      );
      expect(hdkey.publicKey.toString("hex")).toBe(
        "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
      );
      expect(hdkey.extendedPublicKey).toBe(
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
      );
      expect(hdkey.extendedPrivateKey).toBe(
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
      );
    });

    test("chain m/0", () => {
      const child = hdkey.derive("m/0");
      expect(child.parentFingerprint!.toString("hex")).toBe("bd16bee5");
      expect(child.chainCode.toString("hex")).toBe(
        "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
      );
    });

    test("chain m/0/2147483647'", () => {
      const child = hdkey.derive("m/0/2147483647'");
      expect(child.parentFingerprint!.toString("hex")).toBe("5a61ff8e");
      expect(child.chainCode.toString("hex")).toBe(
        "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
      );
    });

    test("chain m/0/2147483647'/1", () => {
      const child = hdkey.derive("m/0/2147483647'/1");
      expect(child.parentFingerprint!.toString("hex")).toBe("d8ab4937");
      expect(child.chainCode.toString("hex")).toBe(
        "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
      );
    });

    test("chain m/0/2147483647'/1/2147483646'", () => {
      const child = hdkey.derive("m/0/2147483647'/1/2147483646'");
      expect(child.parentFingerprint!.toString("hex")).toBe("78412e3a");
      expect(child.chainCode.toString("hex")).toBe(
        "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
      );
    });

    test("chain m/0/2147483647'/1/2147483646'/2", () => {
      const child = hdkey.derive("m/0/2147483647'/1/2147483646'/2");
      expect(child.parentFingerprint!.toString("hex")).toBe("31a507b8");
      expect(child.chainCode.toString("hex")).toBe(
        "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
      );
      expect(child.extendedPublicKey).toBe(
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
      );
    });
  });

  describe("test vector 3", () => {
    const seed = Buffer.from(
      "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
      "hex"
    );
    const hdkey = HDKey.parseMasterSeed(seed);

    test("chain m", () => {
      expect(hdkey.extendedPublicKey).toBe(
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
      );
      expect(hdkey.extendedPrivateKey).toBe(
        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
      );
    });

    test("chain m/0'", () => {
      const child = hdkey.derive("m/0'");
      expect(child.extendedPublicKey).toBe(
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
      );
      expect(child.extendedPrivateKey).toBe(
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
      );
    });
  });
});

describe("derive (ed25519)", () => {
  describe("test vector 1", () => {
    const seed = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
    const hdkey = HDKey.parseEd25519Seed(seed);

    test("chain m", () => {
      expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");
      expect(hdkey.chainCode.toString("hex")).toBe(
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
      );
      expect(hdkey.privateKey!.toString("hex")).toBe(
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
      );
      expect(hdkey.publicKey.toString("hex")).toBe(
        "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
      );

      const derived = hdkey.derive("m");
      expect(hdkey.chainCode).toBe(derived.chainCode);
      expect(hdkey.privateKey).toBe(derived.privateKey);
      expect(hdkey.publicKey).toBe(derived.publicKey);
    });

    test("chain m/0'", () => {
      const child = hdkey.derive("m/0'");
      expect(child.parentFingerprint!.toString("hex")).toBe("ddebc675");
      expect(child.chainCode.toString("hex")).toBe(
        "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
      );
    });

    test("chain m/0'/1'", () => {
      const child = hdkey.derive("m/0'/1'");
      expect(child.parentFingerprint!.toString("hex")).toBe("13dab143");
      expect(child.chainCode.toString("hex")).toBe(
        "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"
      );
    });

    test("chain m/0'/1'/2'", () => {
      const child = hdkey.derive("m/0'/1'/2'");
      expect(child.parentFingerprint!.toString("hex")).toBe("ebe4cb29");
      expect(child.chainCode.toString("hex")).toBe(
        "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"
      );
    });

    test("chain m/1'/1'/2'/2'", () => {
      const child = hdkey.derive("m/0'/1'/2'/2'");
      expect(child.parentFingerprint!.toString("hex")).toBe("316ec1c6");
      expect(child.chainCode.toString("hex")).toBe(
        "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"
      );
    });

    test("chain m/1'/1'/2'/2'/1000000000'", () => {
      const child = hdkey.derive("m/0'/1'/2'/2'/1000000000'");
      expect(child.parentFingerprint!.toString("hex")).toBe("d6322ccd");
      expect(child.chainCode.toString("hex")).toBe(
        "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"
      );
    });

    test("parent key -> non-hardened child key", () => {
      expect(() => {
        hdkey.derive("m/0");
      }).toThrow(/not supported/);
    });
  });

  describe("test vector 2", () => {
    const seed = Buffer.from(
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      "hex"
    );
    const hdkey = HDKey.parseEd25519Seed(seed);

    test("chain m", () => {
      expect(hdkey.parentFingerprint.toString("hex")).toBe("00000000");
      expect(hdkey.chainCode.toString("hex")).toBe(
        "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"
      );
      expect(hdkey.privateKey!.toString("hex")).toBe(
        "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
      );
      expect(hdkey.publicKey.toString("hex")).toBe(
        "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"
      );
    });

    test("chain m/0'", () => {
      const child = hdkey.derive("m/0'");
      expect(child.parentFingerprint!.toString("hex")).toBe("31981b50");
      expect(child.chainCode.toString("hex")).toBe(
        "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"
      );
    });

    test("chain m/0'/2147483647'", () => {
      const child = hdkey.derive("m/0'/2147483647'");
      expect(child.parentFingerprint!.toString("hex")).toBe("1e9411b1");
      expect(child.chainCode.toString("hex")).toBe(
        "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"
      );
    });

    test("chain m/0'/2147483647'/1'", () => {
      const child = hdkey.derive("m/0'/2147483647'/1'");
      expect(child.parentFingerprint!.toString("hex")).toBe("fcadf38c");
      expect(child.chainCode.toString("hex")).toBe(
        "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"
      );
    });

    test("chain m/0'/2147483647'/1'/2147483646'", () => {
      const child = hdkey.derive("m/0'/2147483647'/1'/2147483646'");
      expect(child.parentFingerprint!.toString("hex")).toBe("aca70953");
      expect(child.chainCode.toString("hex")).toBe(
        "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"
      );
    });

    test("chain m/0'/2147483647'/1'/2147483646'/2'", () => {
      const child = hdkey.derive("m/0'/2147483647'/1'/2147483646'/2'");
      expect(child.parentFingerprint!.toString("hex")).toBe("422c654b");
      expect(child.chainCode.toString("hex")).toBe(
        "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4"
      );
      expect(child.privateKey!.toString("hex")).toBe(
        "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d"
      );
      expect(child.publicKey.toString("hex")).toBe(
        "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"
      );
    });
  });
});
