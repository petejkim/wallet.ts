import Mnemonic from '.'

describe('generate', () => {
  test('generates mnemonic phrase from entropy', () => {
    const testCases: { [key: string]: string } = {
      '4d3ef17b17a8a7ec7dfe3e112f7a61f6':
        'essay wasp gain consider media wage wave sick bachelor knock observe undo',
      baa076aafddbeb78ea973289feb05383:
        'rival admit primary wing salt round prevent town measure void belt almost',
      '50df9ecd8b1afc4f4afa49563b8b8cdc':
        'express woman recall bike quit chicken cloud empty file sword tobacco rib'
    }

    Object.keys(testCases).forEach(hex => {
      const entropy = Buffer.from(hex, 'hex')
      const phrase = testCases[hex]
      const mnemonic = Mnemonic.generate(entropy)
      if (mnemonic) {
        expect(mnemonic.entropy.toString('hex')).toBe(hex)
        expect(mnemonic.phrase).toBe(phrase)
        expect(mnemonic.words).toEqual(phrase.split(' '))
      } else {
        expect(mnemonic).not.toBe(null)
      }
    })
  })

  test('returns null when an entropy with an invalid length is passed', () => {
    const testCases: string[] = [
      '4d3ef17b17a8a7ec7dfe3e112f7a61',
      'baa076aafddbeb78ea973289feb053',
      '50df9ecd8b1afc4f4afa49563b'
    ]

    testCases.forEach(hex => {
      let entropy = Buffer.from(hex, 'hex')
      expect(Mnemonic.generate(entropy)).toBe(null)
    })
  })
})

describe('parse', () => {
  test('parses mnemonic, verifies checksum, and decodes back to entropy', () => {
    const testCases: { [key: string]: string } = {
      'essay wasp gain consider media wage wave sick bachelor knock observe undo':
        '4d3ef17b17a8a7ec7dfe3e112f7a61f6',
      'rival admit primary wing salt round prevent town measure void belt almost':
        'baa076aafddbeb78ea973289feb05383',
      'express woman recall bike quit chicken cloud empty file sword tobacco rib':
        '50df9ecd8b1afc4f4afa49563b8b8cdc'
    }

    Object.keys(testCases).forEach(phrase => {
      const hex = testCases[phrase]
      const mnemonic = Mnemonic.parse(phrase)
      if (mnemonic) {
        expect(mnemonic.entropy.toString('hex')).toBe(hex)
        expect(mnemonic.phrase).toBe(phrase)
        expect(mnemonic.words).toEqual(phrase.split(' '))
      } else {
        expect(mnemonic).not.toBe(null)
      }
    })
  })

  test('returns null when verification fails', () => {
    const testCases: string[] = [
      'essay wasp gain consider media wage wave sick bachelor knock observe',
      'essay wasp gain consider media wage wave sick bachelor knock observe uncle',
      'river admit primary wing salt round prevent town measure void belt almost',
      'express woman recall biology quit chicken cloud empty file sword tobacco rib'
    ]

    testCases.forEach(phrase => {
      expect(Mnemonic.parse(phrase)).toBe(null)
    })
  })
})

describe('toSeed', () => {
  test('returns a binary seed derived from a mnemonic phrase', () => {
    const testCases: { [key: string]: string } = {
      'essay wasp gain consider media wage wave sick bachelor knock observe undo':
        'b7df235f1e8addda6befbdf66f4df613474e8ff6041c7826e4df7fa68aa8c244a1d687eda050f97fc20fc2fcd8c09e19ef21d6c14f523639b033e9fc4e6375a6',
      'rival admit primary wing salt round prevent town measure void belt almost':
        '267d6fe81adc779fd2e875d62739cc67690af67025bca8fc6b1f5f3228fb312a1a9b10dedbb3cffc62730438f5afc8725dac6ee11fcd319b98611863226a2957',
      'express woman recall bike quit chicken cloud empty file sword tobacco rib':
        'c35ecec5b1986cd3a1407bc3c829610eb5fc9497e59f31c151a5ce422c7ff7e68bdf3343343605a53db8e7376a932a74b3e08296c0b51476f3d288b750089d9d'
    }

    Object.keys(testCases).forEach(phrase => {
      const seed = testCases[phrase]
      const mnemonic = Mnemonic.parse(phrase)
      if (mnemonic) {
        expect(mnemonic.toSeed().toString('hex')).toBe(seed)
      } else {
        expect(mnemonic).not.toBe(null)
      }
    })
  })
})
