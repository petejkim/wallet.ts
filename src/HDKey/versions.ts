export interface VersionBytes {
  public: number
  private: number
}

const versions: { [asset: string]: VersionBytes } = {
  bitcoinMain: {
    public: 0x0488b21e,
    private: 0x0488ade4
  },
  bitcoinTest: {
    public: 0x043587cf,
    private: 0x04358394
  }
}
export default versions
