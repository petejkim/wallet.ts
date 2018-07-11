import BitcoinAddress from '.'

describe('from', () => {
  test('derives an Bitcoin address from a given compressed public key', () => {
    const testCases: { [key: string]: string } = {
      '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352':
        '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs',
      '023e45506283bb3ffe18025513d459fe0ee0dcf0ce15a2c31e8eecc83f93173871':
        '1GhfPBLChyD2uDVAEGKwZNuZjrSd6WNY1z',
      '0265e20d1c10025e11776306b855ffcfb26176cac2bd4bbfa677056524d100f29a':
        '16zR1jN5KdfBwEvsWuQUANpzLnACb1TWd8',
      '03dbcd1b8c7fad43dafe5a28f593f530a2b30e75f706a5a841b65c6a0dd331a4ef':
        '1DLxqg3Y1EKZ39t94Umner5m7eHbvk76zt',
      '02cf7f68382d44fd74319184ae646b27bcb13a247a5ba08ff9ee0429d2186cd50d':
        '13BPfGT7vqH6myhHc7k6F3iRnLBj3xywW6',
      '031a5acf85fca539622d32116a9bb6679e2046d3172097fdca700e90f8646d03b9':
        '1CWPPiwmDCvRYDmZy1pMenLVMX1jP5QX62'
    }

    Object.keys(testCases).forEach(hex => {
      const publicKey = Buffer.from(hex, 'hex')
      const address = testCases[hex]
      const ea = BitcoinAddress.from(publicKey)
      expect(ea.address).toBe(address)
    })
  })

  test('derives an Bitcoin address from a given uncompressed public key', () => {
    const testCases: { [key: string]: string } = {
      '0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6':
        '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM',
      '043e45506283bb3ffe18025513d459fe0ee0dcf0ce15a2c31e8eecc83f9317387110f016f29cbc43199c04f1d822aa1070799d057aa395c414462b2d8bff8f4942':
        '1K6ojDzpsRUYpP4x4s7KTurXZRmiw1CUwF',
      '0465e20d1c10025e11776306b855ffcfb26176cac2bd4bbfa677056524d100f29a73847a8a221f4e7ddf09c47420c2356d345be57dbd8bc5707fa93f06565e91dc':
        '15Kxj9SRvHu7GRSQWNqfk1gFXKAoBu7y8b',
      '04dbcd1b8c7fad43dafe5a28f593f530a2b30e75f706a5a841b65c6a0dd331a4ef5b334bab26eab7532b1b2ec5a10a29b3926c5aa4af9030aea5c4ca48aea6242b':
        '1PbV3BLAnjDnboK7GKjHDFGuBHnWzN84Na',
      '04cf7f68382d44fd74319184ae646b27bcb13a247a5ba08ff9ee0429d2186cd50d3754d5c0c35d49c1811bf83a490cfc4b7e38e46bb91c833f09ee484e622e574e':
        '12THF1F65RH89KhMw8JZynScbQEe3qUknK',
      '041a5acf85fca539622d32116a9bb6679e2046d3172097fdca700e90f8646d03b99382fb3344bd44f46ed4d423c1b18bd766c80f91617a005a57e8977662079259':
        '17JLCFRFqrYKUb5rMPsehtv2oYv7sx82zc'
    }

    Object.keys(testCases).forEach(hex => {
      const publicKey = Buffer.from(hex, 'hex')
      const address = testCases[hex]
      const ea = BitcoinAddress.from(publicKey)
      expect(ea.address).toBe(address)
    })
  })
})

describe('isValid', () => {
  test('rejects addresses that are too short', () => {
    expect(BitcoinAddress.isValid('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjv')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('16UwLL9Risc3QfPqBUvKofHmBQ7wMtj')).toBe(
      false
    )
  })

  test('rejects addresses that are too long', () => {
    expect(BitcoinAddress.isValid('1K6ojDzpsRUYpP4x4s7KTurXZRmiw1CUwFXa')).toBe(
      false
    )
    expect(
      BitcoinAddress.isValid('1K6ojDzpsRUYpP4x4s7KTurXZRmiw1CUwFXaB')
    ).toBe(false)
  })

  test('rejects addresses that have invalid checksum', () => {
    expect(BitcoinAddress.isValid('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvL')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('1K6ojDzpsRUYpP4x4s7KTurXZRmiw1CUwG')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('15Kxj9SRvHu7GRSQWNqfk1gFXKAoBu7y8a')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('1PbV3BLAnjDnboK7GKjHDFGuBHnWzN84Nb')).toBe(
      false
    )
  })

  test('rejects addresses with invalid characters', () => {
    expect(BitcoinAddress.isValid('1 UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('1K6ojDzp$RUYpP4x4s7KTurXZRmiw1CUwF')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('15!xj9SRvHu7GRSQWNqfk1gFXKAoBu7y8b')).toBe(
      false
    )
    expect(BitcoinAddress.isValid('1PbV3BLAnjDnboK7GKjHDF>uBHnWzN84Na')).toBe(
      false
    )
  })

  test('accepts valid addresses', () => {
    expect(BitcoinAddress.isValid('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')).toBe(
      true
    )
    expect(BitcoinAddress.isValid('1K6ojDzpsRUYpP4x4s7KTurXZRmiw1CUwF')).toBe(
      true
    )
    expect(BitcoinAddress.isValid('15Kxj9SRvHu7GRSQWNqfk1gFXKAoBu7y8b')).toBe(
      true
    )
    expect(BitcoinAddress.isValid('1PbV3BLAnjDnboK7GKjHDFGuBHnWzN84Na')).toBe(
      true
    )
    expect(BitcoinAddress.isValid('12THF1F65RH89KhMw8JZynScbQEe3qUknK')).toBe(
      true
    )
    expect(BitcoinAddress.isValid('17JLCFRFqrYKUb5rMPsehtv2oYv7sx82zc')).toBe(
      true
    )
    expect(BitcoinAddress.isValid('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')).toBe(
      true
    )
  })
})
