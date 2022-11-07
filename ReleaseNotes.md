# Release 4.0.0

- Modify ECPublicKey's export API
- Change ECPrivateKeyImpl's underlying data type to EVP_PKEY
- Remove all usage of deprecated low level OpenSSL-API
- Make EllipticCurvePoint generic in a Curve type
- Upgrade OpenSSL version to 3.0.7
- Change Xcode version to 14.0

# Release 3.0.3

- Fix CMAC method `aes128cbc(key:, data:) throws -> Data`
- Change Xcode version to 13.3.1
- Upgrade OpenSSL version to 3.0.3

# Release 3.0.2

# OpenSSL 3.0.2

  - Upgrade to OpenSSL 3.0.2
  - Fix some of the introduced deprecations
  - Add support for CMSContentInfo Encryption

# Release 1.0.1

- SDK 15
- update OpenSSL to 1.1.1n

# Release 1.0.0
Initial release with support/wrappers for:

  - X.509 Certificate
  - OCSP Response
  - Key Management
  - Generate Private Key (KeyPair)
  - ECDH Shared Secret computation
  - Verify BrainpoolP256r1 signature
  - PACE protocol map Nonce for Shared Secret derivation
  - MAC calculation


