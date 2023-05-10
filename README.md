# OpenSSL-Swift

Swift extension wrapper for gematik specific crypto operations with embedded OpenSSL

## Overview

This Xcode-project downloads, compiles and embeds OpenSSL version 3.0.2 in a Swift framework that can be included
in MacOS/iOS Frameworks and Apps.

There are three main parts of this project.

1. PreBuildPhase script 'Install OpenSSL' that runs before the OpenSSL target is build.
   Execution of this script [e.g. first time run] takes a while since it compiles and links
   for both MacOS x86_64 and iOS arm64 architectures. Consecutive runs of the script will
   check whether the desired target version is already there and skipping the superfluous steps.
2. COpenSSL module(map) that bridges and exposes the OpenSSL C headers to Swift.
3. OpenSSL target and resulting framework that can be included in external projects.
   In this target there is only a limited set of OpenSSL operations available and exposed.
   Generally speaking the ones that are not available in any of the Apple platform included frameworks:
   Security.framework, CommonCrypto and even CryptoKit.
4. Makefile and scripts to support setting up the Xcodeproj and building OpenSSL libraries

### Motivation

As mentioned in the overview, some crypto and security operations are missing in the Apple platform(s)
crypto frameworks. Most significant for Gematik's use-case(s) on iOS is the absence of brainpool elliptic curve support.
These curves are [not part of the TLS standard](https://tools.ietf.org/html/rfc4492#section-5.1.1) and therefore not mandatory for normal HTTPS implementations.
However, Gematik uses brainpool curves exclusively for its 'gem' standard as [advised by BSI](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pd) - Chapter 6.
This leaves us with a gap between what is included in the Apple platforms and Gematik's use-cases.
Therefore we've decided to build a wrapper around a well established and maintained [open source crypto
library](https://github.com/openssl/openssl) that we can access directly from Swift source code.
Accessing OpenSSL crypto operations directly from Swift allows us to not having to manually free the
memory that was allocated by the low-level OpenSSL operation, but instead hide this complex code from
the casual user/developer that may need to use some of the features provided by this framework.

## Getting Started

### Setup for integration

We don't support CocoaPods at all, however it might also work when setup accordingly

**SPM:** Add via XCode or `Package.swift`

```
.package(url: "https://github.com/gematik/OpenSSL-Swift", from: "4.0.0"),
```

 **Carthage:** Put this into your `Cartfile`:

```
github "gematik/OpenSSL-Swift" ~> 4.0
```

### Setup for development


```shell script
$ make setup
```

Opening `OpenSSL-Swift.xcodeproj` and building/testing a scheme will execute the script `scripts/install_openssl`. The script will perform a download from [OpenSSL](https://www.openssl.org/) and compile frameworks for multiple platform/architecture combinations.

## Supported operations

As mentioned in the Overview section of this document, only a small subset of OpenSSL's operations is made available.
This section describes the operations that are supported.

### X.509 Certificate

Some basic operations on **X.509 based Certificates** are available by this framework's API. Since it's
backed by `OpenSSL` a lot more signature algorithms are supported.

You can instantiate `X509` objects either by `Data` in raw DER-representation or in PEM-representation
(originating form a string which usually starts with *-----BEGIN CERTIFICATE-----*).

```swift
let derEncodedX509Data = Data(base64Encoded: "MIICsTC...")
let x509 = try X509(der: derEncodedX509Data)   
// or
let x509 = try X509(pem: "-----BEGIN CERTIFICATE-----.....".data(using: .ascii))

let issuerOneLine = try x509.issuerOneLine() // "/C=DE/O=gematik GmbH NOT-VALID/OU=Komponenten-CA der Telematikinfrastruktur/CN=GEM.KOMP-CA10 TEST-ONLY"
let sha256Fingerprint = try x509.sha256Fingerprint()
let validatedWithTrustStore = x509.validateWithTrustStore([rootCaCert, otherCaCert])

// If the certificate holder is using a BrainpoolP256r1 key for signing, you can retrieve the public counterpart conveniently
let brainpoolP256r1PublicKey = x509.brainpoolP256r1PublicKey() // `BrainpoolP256r1.Verify.PublicKey?`
```

### OCSP Response

Use OSCP responses to try to validate a status of a given `X509` certificate. 

You can instantiate `OCSPResponse` objects by `Data` in raw DER-representation.

```swift
let ocspResponse = try! OCSPResponse(der: Base64.decode(data: "MIIHBQoBAKCCBv4wggb6Bgkr..."))

print(ocspResponse.status()) // the `OCSPResponse.Status` of the response itself, e.g. .successful, .tryLater ...
print(try vauOcspResponseNoKnownSignerCa.producedAt()) // the `Date` held in the `producedAt` field of the response 

// Check the revocation status `OCSPResponse.CertStatus` for a given certificate with a ocspResponse.
let certificate, certificateIssuer: X509!
print(try ocspResponse.certificateStatus(for: certificate, issuer: certificateIssuer)) // .good, .revoked ...

// Verify the signature on a ocspResponse against a given trust store
let ocspSignerCa, rootCa: X509!
print(try ocspResponse.basicVerifyWith(trustedStore: [ocspSignerCa, rootCa])) // true, false
// Use `OCSPResponse.BasicVerifyOptions` to set certain basic-verify check flags 
// refer to: https://www.openssl.org/docs/man1.1.0/man3/OCSP_resp_get0.html -> OCSP_basic_verify()
// After successful path validation the function returns success if the OCSP_NOCHECKS flag is set.
let options: OCSPResponse.BasicVerifyOptions = [.noChecks]
try vauOcspResponse.basicVerifyWith(trustedStore: [ocspSignerCa, rootCa], options: options)
```

### Cryptographic Message Syntax

CMS-Encryption of a message for (multiple) `X509` recipient certificate(s) (for now only RSA!) is supported. An *Authenticated-Enveloped-Data Content Type* structure using *AES 256 GCM* will be created.

```swift
let x509rsa = try X509(pem: x509rsaPem.data(using: .utf8)!)
let x509ecc = try X509(pem: x509eccPem.data(using: .utf8)!)
let recipients = [x509rsa, x509ecc]
let data = message.data(using: .utf8)!
let cms = try CMSContentInfo.encryptPartial(data: data)
try cms.addRecipientsRSAOnly(recipients)
try cms.final(data: data)
print(cms.derBytes?.hexString())
```

### Key Management

Cryptographic operations are often based on public / private keys that here are represented by the
`ECPublicKey` and `PrivateKey` protocols.
You can instantiate them by picking implementing classes according to your use case,
e.g. `BrainpoolP256r1.KeyExchange.PublicKey`, `BrainpoolP256r1.KeyExchange.PrivateKey`,... and going on from there.
The public key can be initialized by passing in the elliptic curve point ( 0x4 || x || y) [ANSI X9.62 format] and the
private key as well (0x4 || x || y || k). Where `k` is the private key. The private key can also be initialized by
just `k` as the raw parameter.
A private key can also be randomly generated.

### Generate Private Key (KeyPair)

```swift
let key = try BrainpoolP256r1.KeyExchange.generateKey()
```

### ECDH Shared Secret computation

Deriving a **BrainpoolP256r1** shared secret can be done with the use of `BrainpoolP256r1.KeyExchange.PublicKey` and its
counterpart `BrainpoolP256r1.KeyExchange.PrivateKey` and calling `.sharedSecret(with: peerKey)` method on the said
private key and passing in the public key as the peer.

```swift
let pubKeyx962 = try Data(hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29")
let privateKeyRaw = try Data(hex: "83456D98DEA3435C166385A4E644EBCA588E8A0AA7C811F51FCC736368630206")
let pubKey = try BrainpoolP256r1.KeyExchange.PublicKey(x962: pubKeyx962)
let privateKey = try BrainpoolP256r1.KeyExchange.PrivateKey(raw: privateKeyRaw)
let sharedSecretData = try privateKey.sharedSecret(with: pubKey)
```

### Verify BrainpoolP256r1 signature

```swift
let pubkeyraw = Data[...]
let pubKey = try BrainpoolP256r1.Verify.PublicKey(x962: pubkeyraw)
let derSignature = Data[...]
let signature = try BrainpoolP256r1.Verify.Signature(derRepresentation: derSignature)
let message = "A signed message"

try pubKey.verify(signature: signature, message: message.data(using: .utf8)!)
```

### PACE protocol map Nonce for Shared Secret derivation

The PACE protocol sets up a SecureMessaging channel with strong session keys based on a shared password,
possibly of low entropy.

see: [BSI TR-03110](https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html)

This implementation follows PACE protocol conformance as specified in
[gemSpec_COS_V3.11.0](https://www.vesta-gematik.de/standard/formhandler/64/gemSpec_COS_V3_10_0.pdf) (N085.064)
for establishing a secure communication channel with German health cards (eGK) using **BrainpoolP256r1**.

The algorithm will return a public key to be sent to the peer and a generated keyPair2 for internal use.
The actual secret has then to be derived from a further peer's public key and the previously mentioned keyPair2.

Deriving a **BrainpoolP256r1 PACE** shared secret can be done with the use of a
`BrainpoolP256r1.KeyExchange.PrivateKey`, its peer key counterpart `BrainpoolP256r1.KeyExchange.PublicKey`,
and the plain nonce password (as `Data`) calling `.paceMapNonce(nonce: nonce with: peerKey)` method on the said
private key, passing in the nonce and the public key as the peer.

```swift
let nonce = try Data(hex: "A44248628B8E8B94072EF3843C56E844")
let ownKeyPair1Raw = try Data(hex: "0D7DFFAC3558C4C3C075A0479F4C3A4864DBD8E686CDB154DD0BDD0BA7CE4D51")
let ownKeyPair1 = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(raw: ownKeyPair1Raw)
let peerKeyRaw = try Data(hex: "045CAC41779F548CBE714A08CBCEB40F616B5EFDD59DD3345802027DCB0C3FB02B20DC7A458B7744102DE98D350D4399FEC0F8CC5CCE50317A2CEE3CB418A4DA41")
let peerKey1 = try ECPublicKeyImpl<BrainpoolP256r1.Curve>(x962: peerKeyRaw)
let (ownPubKey2, ownKeyPair2) = try ownPrivateKey1.paceMapNonce(nonce: nonce, peerKey1: peerKey1)

// receive the peer's second publicKey peerPubKey2
let sharedSecret = try ownKeyPair2.sharedSecret(peerPubKey2)
```

### MAC calculation

Generation of a MAC via 128-bit AES-CMAC (CBC-MAC) algorithm as described in 
[RFC: The AES-CMAC Algorithm](https://tools.ietf.org/html/rfc4493) is supported.

```swift
let key = try! Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
let message = try! Data(hex: "")
let cmac = CMAC.aes128cbc(key: key, data: message) // == hex: "bb1d6929e95937287fa37d129b756746"
```

## OpenSSL version update

To update the OpenSSL version embedded with the library you simply update the `scripts/install_openssl` on lines 18:19
with the new OpenSSL version and appropriate SHA256 hash value.