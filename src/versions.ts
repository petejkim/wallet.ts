export interface VersionBytes {
  bip32: {
    public: number
    private: number
  }
  public: number
}

const versions = {
  bitcoinMain: {
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    public: 0
  },
  bitcoinTest: {
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    public: 0
  }
}

export default versions
