//
//  Copyright (c) 2022 gematik GmbH
//  
//  Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
//  the European Commission - subsequent versions of the EUPL (the Licence);
//  You may not use this work except in compliance with the Licence.
//  You may obtain a copy of the Licence at:
//  
//      https://joinup.ec.europa.eu/software/page/eupl
//  
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the Licence is distributed on an "AS IS" basis,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the Licence for the specific language governing permissions and
//  limitations under the Licence.
//  
//

@_implementationOnly import COpenSSL
import Foundation

/// Elliptic Curve private key
public protocol ECPrivateKey where PublicKey: ECPublicKey {
    /// The associated public key type
    associatedtype PublicKey

    /// Initialize a private key for an elliptic curve public key,
    /// the format follows the ANSI X9.62 standard using a byte string of 04 || X || Y || K.
    ///
    /// - Parameter x962: ANSI X9.62 key material
    /// - Throws: `OpenSSLError` when the key could not be initialized
    init(x962: Data) throws

    /// Initialize a private key for an elliptic curve public key,
    /// the raw value is supposed to be K.
    ///
    /// - Parameter raw: Octet-String with K (BIGNUM)
    /// - Throws: `OpenSSLError` when the key could not be initialized
    init(raw: Data) throws

    /// The associated public key
    var publicKey: PublicKey { get }

    /// Generate a key
    ///
    /// - Note: some implementations might not be thread-safe in case of generating keys concurrently due to the fact
    ///         that OpenSSL's random number generator is not thread-safe.
    ///
    /// - Returns: the generated key pair
    /// - Throws: when no key pair could be generated
    static func generateKey() throws -> Self
}

typealias EVP_PKEY = OpaquePointer

final class ECPrivateKeyImpl<Curve: ECCurve>: ECPrivateKey {
    private let pkey: EVP_PKEY
    private let associatedPublicKey: ECPublicKeyImpl<Curve>

    /// Generate a key
    ///
    /// - Note: this initializer is not thread-safe due to the underlying openssl randomization not being thread-safe.
    ///
    /// [REQ:gemSpec_Krypt:GS-A_4368] Key generation delegation to OpenSSL according to the `ECCurve` group.
    /// [REQ:gemSpec_Krypt:GS-A_4361]
    /// [REQ:gemSpec_Krypt:GS-A_4357]
    ///
    /// - Throws: when no key pair could be generated
    init() throws {
        guard let pkey = EVP_EC_gen_wrapped(Curve.name.asCChar) else {
            throw OpenSSLError(name: "Could not generate key pair.")
        }
        self.pkey = pkey

        // create the associated public key from (generated) pkey w/o the private key data portion
        let dup = EVP_PKEY_dup(pkey)
        defer { EVP_PKEY_free(dup) }
        let pubKeyCompactData = try publicKeyCompactDataFromEvpPkey(dup)
        associatedPublicKey = try ECPublicKeyImpl(compact: pubKeyCompactData)
    }

    /// Initialize a private key (key pair) from data.
    ///
    /// - Parameter data: Data encoding the private key; the expected representation is 0x4 || x || y || k
    /// - Throws: OpenSSLError
    init(data: Data) throws {
        // swiftlint:disable:previous function_body_length
        let group = Curve.group

        // The expected representation is 0x4 || x || y || k
        guard data.count == 1 + 3 * group.coordinateByteCount else {
            throw OpenSSLError(name: "Unexpected encoding for private key data")
        }
        let offsetK = 1 + (2 * group.coordinateByteCount)
        let pubData = data[..<offsetK]
        let privData = data[offsetK...]

        var pkey = EVP_PKEY_new()
        var priv: BIGNUM?
        defer { BN_free(priv) }
        priv = privData.withUnsafeBytes { (privDataPointer: UnsafeRawBufferPointer) -> BIGNUM? in
            let privDataPointerBaseAddress = privDataPointer.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return BN_bin2bn(privDataPointerBaseAddress, CInt(privDataPointer.count), priv)
        }

        // set up OSSL_PARAMs
        let osslParamBuilder = OSSL_PARAM_BLD_new()
        defer { OSSL_PARAM_BLD_free(osslParamBuilder) }
        guard
            OSSL_PARAM_BLD_push_utf8_string(osslParamBuilder, OSSL_PKEY_PARAM_GROUP_NAME_W, Curve.name.asCChar, 0) == 1,
            OSSL_PARAM_BLD_push_BN(osslParamBuilder, OSSL_PKEY_PARAM_PRIV_KEY_W, priv) == 1
        else {
            throw OpenSSLError(name: "Error setting up OSSL_PARAM")
        }

        try pubData.withUnsafeBytes { buffer in
            guard
                let bufferPointer = buffer.bindMemory(to: UInt8.self).baseAddress,
                OSSL_PARAM_BLD_push_octet_string(
                    osslParamBuilder,
                    OSSL_PKEY_PARAM_PUB_KEY_W,
                    bufferPointer,
                    buffer.count
                ) == 1
            else {
                throw OpenSSLError(name: "Error setting up OSSL_PARAM")
            }
        }
        let osslParams = OSSL_PARAM_BLD_to_param(osslParamBuilder)
        defer { OSSL_PARAM_free(osslParams) }

        // write OSSL_PARAMs to EVP_PKEY
        let ctx = EVP_PKEY_CTX_new_from_name(nil, EVP_PKEY_CTX_NAME_EC, nil)
        defer { EVP_PKEY_CTX_free(ctx) }
        guard
            EVP_PKEY_fromdata_init(ctx) == 1,
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR_W, osslParams) == 1,
            let pkey = pkey
        else {
            throw OpenSSLError(name: "Error reading data to pkey")
        }

        // NOTE: EVP_PKEY_fromdata checks whether provided (public key) point is on the curve,
        //  but not whether the public and private components have the correct mathematical relationship to each other
        //  --> validate
        let validationContext = EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
        defer { EVP_PKEY_CTX_free(validationContext) }
        // NOTE: Functions return -2 if the operation is not supported for the specific algorithm. Not an issue now.
        guard
            EVP_PKEY_param_check(validationContext) > 0,
            EVP_PKEY_public_check(validationContext) > 0,
            EVP_PKEY_private_check(validationContext) > 0,
            EVP_PKEY_pairwise_check(validationContext) > 0
        else {
            throw OpenSSLError(name: "Error when validating the components of the key (bad data?)")
        }

        self.pkey = pkey
        associatedPublicKey = try ECPublicKeyImpl(x962: pubData)
    }

    convenience init(x962: Data) throws {
        let group = Curve.group

        // Before we do anything, we validate that the raw representation has the right number of bytes.
        // Must be |0x04| + size(x-component) + size(y-component) + size(k)
        let length = x962.count
        guard length == (group.coordinateByteCount * 3) + 1 else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }
        try self.init(data: x962)
    }

    convenience init(raw: Data) throws {
        let group = Curve.group

        // Before we do anything, we validate that the raw representation has the right number of bytes.
        // OpenSSL will quietly accept shorter byte counts, though it will reject longer ones.
        let length = raw.count
        guard length <= group.coordinateByteCount else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }

        // The raw representation is just the bytes that make up k.
        // swiftlint:disable:next identifier_name
        let k = try BigNumber(bytes: raw)

        // Now calculate the public key data.
        let point = try EllipticCurvePoint<Curve>(multiplyWithBasePoint: k)

        let pubKeyData = try point.export(pointConversion: .uncompressed)
        try self.init(x962: pubKeyData + raw)
    }

    deinit {
        EVP_PKEY_free(pkey)
    }

    var publicKey: ECPublicKeyImpl<Curve> {
        associatedPublicKey
    }

    func rawPrivateKeyData() throws -> Data {
        // To extract the private key data, one would use EVP_PKEY_get_raw_private_key() but
        //  as of now, it does not support Brainpool curves.
        //  see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_get_raw_public_key.html
        var osslParamsToData: UnsafeMutablePointer<OSSL_PARAM>?
        defer { OSSL_PARAM_free(osslParamsToData) }
        var bigNum: BIGNUM?
        defer { BN_free(bigNum) }
        guard
            EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY_W, &osslParamsToData) == 1,
            EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY_W, &bigNum) == 1
        else {
            throw OpenSSLError(name: "Internal error extracting private key data")
        }

        let size = (BN_num_bits(bigNum) + 7) / 8
        var bytes = [UInt8](repeating: 0x0, count: Int(size))

        guard BN_bn2bin(bigNum, &bytes) > 0 else {
            throw OpenSSLError(name: "Internal error extracting private key data")
        }
        return Data(bytes)
    }

    func multiply(with point: EllipticCurvePoint<Curve>) throws -> EllipticCurvePoint<Curve> {
        /* Extract the private key material, then try a multiplication with the given point */
        let scalar = try BigNumber(bytes: rawPrivateKeyData())
        return try point.multiply(scalar)
    }

    func sign(digest: Digest) throws -> ECDSASignature {
        try digest.withUnsafeBytes { (digestPtr: UnsafeRawBufferPointer) in
            let signingContext = EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
            defer { EVP_PKEY_CTX_free(signingContext) }
            guard EVP_PKEY_sign_init(signingContext) == 1 else {
                throw OpenSSLError(name: "Error setting up the signature verification context")
            }
            // step 1: determine resulting signature length
            let digestPtrBase = digestPtr.bindMemory(to: UInt8.self).baseAddress
            var sigLen = 0
            guard EVP_PKEY_sign(signingContext, nil, &sigLen, digestPtrBase, digestPtr.count) == 1 else {
                throw OpenSSLError(name: "Error in sign step 1")
            }
            // step 2: write signature to sig
            let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sigLen)
            guard EVP_PKEY_sign(signingContext, sig, &sigLen, digestPtrBase, digestPtr.count) == 1 else {
                throw OpenSSLError(name: "Error in sign step 2")
            }

            return try ECDSASignature(derRepresentation: Data(bytesNoCopy: sig, count: Int(sigLen), deallocator: .free))
        }
    }

    class func generateKey() throws -> ECPrivateKeyImpl {
        try ECPrivateKeyImpl()
    }
}

extension ECPrivateKeyImpl: DiffieHellman {
    public func sharedSecret(with peerKey: ECPublicKeyImpl<Curve>) throws -> Data {
        let sharedSecretDerivationContext = EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
        defer { EVP_PKEY_CTX_free(sharedSecretDerivationContext) }
        guard
            EVP_PKEY_derive_init(sharedSecretDerivationContext) == 1,
            EVP_PKEY_derive_set_peer(sharedSecretDerivationContext, peerKey.pkey) == 1
        else {
            throw OpenSSLError(name: "Error setting up the shared secret derivation context")
        }
        // step 1: determine resulting shared secret length
        var keyLen = 0
        guard EVP_PKEY_derive(sharedSecretDerivationContext, nil, &keyLen) == 1 else {
            throw OpenSSLError(name: "Error in sharedSecretDerivation step 1")
        }
        // step 2: write shared secret to key
        let key = UnsafeMutablePointer<UInt8>.allocate(capacity: keyLen)
        guard EVP_PKEY_derive(sharedSecretDerivationContext, key, &keyLen) == 1 else {
            throw OpenSSLError(name: "Error in sharedSecretDerivation step 2")
        }

        return Data(bytesNoCopy: key, count: Int(keyLen), deallocator: .free)
    }
}

extension ECPrivateKeyImpl: DigestSigner {}

func publicKeyCompactDataFromEvpPkey(_ pkey: OpaquePointer?) throws -> Data {
    // - NOTE: Unexpectedly, the output format of EVP_PKEY_todata() is POINT_CONVERSION_COMPRESSED(!) for the pub key
    //      and the following implementation for now relies on that fact (that might be subject to change soon).
    // see: https://github.com/openssl/openssl/issues/16595 and
    //      https://github.com/openssl/openssl/pull/16624
    var osslParamsToData: UnsafeMutablePointer<OSSL_PARAM>?
    defer { OSSL_PARAM_free(osslParamsToData) }
    guard EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY_W, &osslParamsToData) == 1 else {
        throw OpenSSLError(name: "Unable to retrieve public key data")
    }

    let pubParam = OSSL_PARAM_locate(osslParamsToData, OSSL_PKEY_PARAM_PUB_KEY_W)
    var pubBuffer: UnsafeRawPointer?
    var size = 0
    guard
        OSSL_PARAM_get_octet_string_ptr(pubParam, &pubBuffer, &size) == 1,
        size > 0,
        let safeBuffer = pubBuffer
    else {
        throw OpenSSLError(name: "Unable to retrieve public key data")
    }
    return Data(bytes: safeBuffer, count: size)
}
