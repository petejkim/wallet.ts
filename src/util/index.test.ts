import { uncompressPublicKey } from '.'

describe('uncompressPublicKey', () => {
  test('does nothing and returns the same key if an already uncompressed public key is given', () => {
    const testCases: string[] = [
      '04bbcf65f8074fe2fba2b5a7ea44fcae88f7c12d0a51aa9c9193336739fee8167f72da911f6377971e1dcd4ff589f3ef84f51d4adde93b68498470b03399a8c451',
      '0406d900ae61f6f6a5fc73a1d0e7f6f6b0b22fcb31496a575ed5b07932b4cff0ee8479690287883c69f1f9e293b3397c9318ae13ec2144df29c8164d6cf935f5b6',
      '043ad5f4d0042a54769c390668bd120caa20ff193e54887342b1ccbe6a4df0e448c9e1517ddf27378ef0d75d964b21684d3f6a1d22d6d4c36898978afff9f55593',
      '04ce4bef9198f26a815f63e74c93b41d98d38c890d3bd19d65a55ede7efc5c8e5461caf6646800d4b44a38e39e81923158f10919d1aa791e151dc1f422a554c67e'
    ]

    testCases.forEach(hex => {
      const publicKey = Buffer.from(hex, 'hex')
      expect(uncompressPublicKey(publicKey).toString('hex')).toBe(hex)
    })
  })

  test('returns an uncompressed representation of a given comprsesed public key', () => {
    const testCases: { [key: string]: string } = {
      '03bbcf65f8074fe2fba2b5a7ea44fcae88f7c12d0a51aa9c9193336739fee8167f':
        '04bbcf65f8074fe2fba2b5a7ea44fcae88f7c12d0a51aa9c9193336739fee8167f72da911f6377971e1dcd4ff589f3ef84f51d4adde93b68498470b03399a8c451',
      '0206d900ae61f6f6a5fc73a1d0e7f6f6b0b22fcb31496a575ed5b07932b4cff0ee':
        '0406d900ae61f6f6a5fc73a1d0e7f6f6b0b22fcb31496a575ed5b07932b4cff0ee8479690287883c69f1f9e293b3397c9318ae13ec2144df29c8164d6cf935f5b6',
      '033ad5f4d0042a54769c390668bd120caa20ff193e54887342b1ccbe6a4df0e448':
        '043ad5f4d0042a54769c390668bd120caa20ff193e54887342b1ccbe6a4df0e448c9e1517ddf27378ef0d75d964b21684d3f6a1d22d6d4c36898978afff9f55593',
      '02ce4bef9198f26a815f63e74c93b41d98d38c890d3bd19d65a55ede7efc5c8e54':
        '04ce4bef9198f26a815f63e74c93b41d98d38c890d3bd19d65a55ede7efc5c8e5461caf6646800d4b44a38e39e81923158f10919d1aa791e151dc1f422a554c67e'
    }

    Object.keys(testCases).forEach(compressedHex => {
      const uncompressedHex = testCases[compressedHex]
      const compressedKey = Buffer.from(compressedHex, 'hex')
      expect(uncompressPublicKey(compressedKey).toString('hex')).toBe(
        uncompressedHex
      )
    })
  })

  test('throws an error if an invalid public key is given', () => {
    const testCases: string[] = [
      '03bbcf65f8074fe2fba2b5a7ea44fcae88f7c12d0a51aa9c9193336739fee8167f72da911f6377971e1dcd4ff589f3ef84f51d4adde93b68498470b03399a8c451',
      '04ce4bef9198f26a815f63e74c93b41d98d38c890d3bd19d65a55ede7efc5c8e5461caf6646800d4b44a38e39e81923158f10919d1aa791e151dc1f422a554c67e00',
      '04ce4bef9198f26a815f63e74c93b41d98d38c890d3bd19d65a55ede7efc5c8e5461caf6646800d4b44a38e39e81923158f10919d1aa791e151dc1f422a554c6',
      '03bbcf65f8074fe2fba2b5a7ea44fcae88f7c12d0a51aa9c9193336739fee8167f0a',
      '01bbcf65f8074fe2fba2b5a7ea44fcae88f7c12d0a51aa9c9193336739fee8167f',
      '02ffd900ae61f6f6a5fc73a1d0e7f6f6b0b22fcb31496a575ed5b07932b4cff0ee',
      '0206d900ae61f6f6a5fc73a1d0e7f6f6b0b22fcb31496a575ed5b07932b4cff0'
    ]

    testCases.forEach(hex => {
      const publicKey = Buffer.from(hex, 'hex')
      expect(() => uncompressPublicKey(publicKey)).toThrow(/invalid/)
    })
  })
})
