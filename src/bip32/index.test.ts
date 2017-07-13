import { HDKey } from '.'

describe('parseMasterSeed', () => {
  test('initialize an instance of HDKey from master seed', () => {
    const seed = Buffer.from(
      'b7df235f1e8addda6befbdf66f4df613474e8ff6041c7826e4df7fa68aa8c244a1d687eda050f97fc20fc2fcd8c09e19ef21d6c14f523639b033e9fc4e6375a6',
      'hex'
    )
    const hdkey = HDKey.parseMasterSeed(seed)
    expect(hdkey.privateKey && hdkey.privateKey.toString('hex')).toBe(
      'ae4ae84fd731b25809815c22f5de48ef4b769484b4a2d2ae5c47f622fbda8e9f'
    )
    expect(hdkey.publicKey.toString('hex')).toBe(
      '02f8205ad1bb6e9680bd920c9ae4ccd51a2a6f466b330bbe6792a831ae2c50a6d3'
    )
    expect(hdkey.depth).toBe(0)
    expect(hdkey.index).toBe(0)
    expect(hdkey.parentFingerprint).toBe(null)
  })
})

describe('parseExtendedKey', () => {
  test('initialize an instance of HDKey from an extended private key', () => {
    const hdkey = HDKey.parseExtendedKey(
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    )

    expect(hdkey.depth).toBe(0)
    expect(hdkey.index).toBe(0)
    expect(hdkey.parentFingerprint).toBe(null)

    expect(hdkey.publicKey.toString('hex')).toBe(
      '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
    )
    expect(hdkey.privateKey && hdkey.privateKey.toString('hex')).toBe(
      'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
    )

    expect(hdkey.extendedPublicKey).toBe(
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    )
    expect(hdkey.extendedPrivateKey).toBe(
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    )
  })

  test('initialize an instance of HDKey from an extended public key', () => {
    const hdkey = HDKey.parseExtendedKey(
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    )

    expect(hdkey.depth).toBe(0)
    expect(hdkey.index).toBe(0)
    expect(hdkey.parentFingerprint).toBe(null)

    expect(hdkey.publicKey.toString('hex')).toBe(
      '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
    )
    expect(hdkey.privateKey).toBe(null)

    expect(hdkey.extendedPublicKey).toBe(
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    )
    expect(hdkey.extendedPrivateKey).toBe(null)
  })

  test('initialize an instance of HDKey from a derived key', () => {
    const hdkey = HDKey.parseExtendedKey(
      'xprv9uHRZZhbkedL7ChPMJeZbg3bP5LUqJsrpZ393GbdKnoNwZ4dVuA8mv9ZgAoi53z4Uq9EMgtVKFswXRjgiViKUbCnQ2K7uDVbKgCubQjqfDg'
    )
    expect(hdkey.depth).toBe(1)
    expect(hdkey.index).toBe(2)
    expect(
      hdkey.parentFingerprint && hdkey.parentFingerprint.toString('hex')
    ).toBe('3442193e')

    expect(hdkey.publicKey.toString('hex')).toBe(
      '02fd648f85194d8cad102d63aa29bf86336ed148134eb521c59436500c15588fff'
    )
    expect(hdkey.privateKey && hdkey.privateKey.toString('hex')).toBe(
      '271614f2ca446df6e17e3ea92dacc70a0b6360bf831648a42508e7918a71db8a'
    )

    expect(hdkey.extendedPrivateKey).toBe(
      'xprv9uHRZZhbkedL7ChPMJeZbg3bP5LUqJsrpZ393GbdKnoNwZ4dVuA8mv9ZgAoi53z4Uq9EMgtVKFswXRjgiViKUbCnQ2K7uDVbKgCubQjqfDg'
    )
    expect(hdkey.extendedPublicKey).toBe(
      'xpub68Gmy5EVb2BdKgmrTLBZxozKw7AyEmbiBmxjqf1Et8LMpMPn3SUPKiU3XTTrgkJzWbuF8h8E4Ah1m4bWsVqaPa3fzD6p7qEWrFTrgRR1iAe'
    )
  })
})

describe('derive', () => {
  describe('test vector 1', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')
    const hdkey = HDKey.parseMasterSeed(seed)

    test('chain m', () => {
      expect(hdkey.extendedPublicKey).toBe(
        'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
      )
      expect(hdkey.extendedPrivateKey).toBe(
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
      )

      const derived = hdkey.derive('m')
      expect(hdkey.extendedPublicKey).toBe(derived.extendedPublicKey)
      expect(hdkey.extendedPrivateKey).toBe(derived.extendedPrivateKey)
    })

    test("chain m/0'", () => {
      const child = hdkey.derive("m/0'")
      expect(child.extendedPublicKey).toBe(
        'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
      )
    })

    test("chain m/0'/1", () => {
      const child = hdkey.derive("m/0'/1")
      expect(child.extendedPublicKey).toBe(
        'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
      )
    })

    test("chain m/0'/1/2'", () => {
      const child = hdkey.derive("m/0'/1/2'")
      expect(child.extendedPublicKey).toBe(
        'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
      )
    })

    test("chain m/1'/1/2'/2", () => {
      const child = hdkey.derive("m/0'/1/2'/2")
      expect(child.extendedPublicKey).toBe(
        'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
      )
    })

    test("chain m/1'/1/2'/2/1000000000", () => {
      const child = hdkey.derive("m/0'/1/2'/2/1000000000")
      expect(child.extendedPublicKey).toBe(
        'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
      )
    })

    test('derive key from a derived key', () => {
      const child = hdkey.derive("m/0'").derive('m/1')
      expect(child.extendedPublicKey).toBe(
        'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
      )
    })

    test('public parent key -> hardened child key', () => {
      const parent = HDKey.parseExtendedKey(hdkey.extendedPublicKey)
      expect(() => {
        parent.derive("m/0'")
      }).toThrow(/hardened/)
    })

    test('public parent key -> non-hardened child key', () => {
      const parent = HDKey.parseExtendedKey(hdkey.extendedPublicKey)
      const child = parent.derive('m/0')
      expect(child.extendedPublicKey).toBe(
        'xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1'
      )
      expect(child.extendedPrivateKey).toBe(null)
    })
  })

  describe('test vector 2', () => {
    const seed = Buffer.from(
      'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
      'hex'
    )
    const hdkey = HDKey.parseMasterSeed(seed)

    test('chain m', () => {
      expect(hdkey.extendedPublicKey).toBe(
        'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
      )
      expect(hdkey.extendedPrivateKey).toBe(
        'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
      )
    })

    test('chain m/0', () => {
      const child = hdkey.derive('m/0')
      expect(child.extendedPublicKey).toBe(
        'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
      )
    })

    test("chain m/0/2147483647'", () => {
      const child = hdkey.derive("m/0/2147483647'")
      expect(child.extendedPublicKey).toBe(
        'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'
      )
    })

    test("chain m/0/2147483647'/1", () => {
      const child = hdkey.derive("m/0/2147483647'/1")
      expect(child.extendedPublicKey).toBe(
        'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'
      )
    })

    test("chain m/0/2147483647'/1/2147483646'", () => {
      const child = hdkey.derive("m/0/2147483647'/1/2147483646'")
      expect(child.extendedPublicKey).toBe(
        'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'
      )
    })

    test("chain m/0/2147483647'/1/2147483646'/2", () => {
      const child = hdkey.derive("m/0/2147483647'/1/2147483646'/2")
      expect(child.extendedPublicKey).toBe(
        'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
      )
    })
  })

  describe('test vector 3', () => {
    const seed = Buffer.from(
      '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
      'hex'
    )
    const hdkey = HDKey.parseMasterSeed(seed)

    test('chain m', () => {
      expect(hdkey.extendedPublicKey).toBe(
        'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13'
      )
      expect(hdkey.extendedPrivateKey).toBe(
        'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6'
      )
    })

    test("chain m/0'", () => {
      const child = hdkey.derive("m/0'")
      expect(child.extendedPublicKey).toBe(
        'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y'
      )
      expect(child.extendedPrivateKey).toBe(
        'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'
      )
    })
  })
})
