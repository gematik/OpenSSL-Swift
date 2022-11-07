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

/// Elliptic Curve public key
public protocol ECPublicKey {
    /// Initialize a public key from compressed representation
    ///
    /// - Parameter compact: key material
    /// - Throws: `OpenSSLError` when the key could not be initialized
    init(compact: Data) throws

    /// Initialize a public key For an elliptic curve public key,
    /// the format follows the ANSI X9.62 standard using a byte string of 04 || X || Y.
    ///
    /// - Parameter x962: ANSI X9.62 key material
    /// - Throws: `OpenSSLError` when the key could not be initialized
    init(x962: Data) throws

    /// The raw EC Public Key representation in Octet-String
    func rawValue() throws -> Data

    /// The raw EC Public Key representation using ANSI X9.62 standard [04 || X || Y]. (uncompressed)
    func x962Value() throws -> Data

    /// The raw EC Public Key compressed representation
    func compactValue() throws -> Data
}

final class ECPublicKeyImpl<Curve: ECCurve>: ECPublicKey {
    let pkey: EVP_PKEY

    /// Owning Non-copying initializer for EC Public Key
    ///
    /// - Parameter pkey: pointer to the EVP_PKEY to own and manage
    init(pkey: EVP_PKEY) {
        self.pkey = pkey
    }

    /// Initialize a public key from data (regardless whether in compressed or uncompressed representation.
    ///
    /// - Parameter data: Data encoding the public key
    /// - Throws: OpenSSLError
    init(data: Data) throws {
        var pkey = EVP_PKEY_new()

        // set up OSSL_PARAMs
        let osslParamBuilder = OSSL_PARAM_BLD_new()
        defer { OSSL_PARAM_BLD_free(osslParamBuilder) }
        guard
            OSSL_PARAM_BLD_push_utf8_string(osslParamBuilder, OSSL_PKEY_PARAM_GROUP_NAME_W, Curve.name.asCChar, 0) == 1
        else {
            throw OpenSSLError(name: "Error setting up OSSL_PARAM")
        }

        try data.withUnsafeBytes { buffer in
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
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY_W, osslParams) == 1,
            let pkey = pkey
        else {
            throw OpenSSLError(name: "Error reading data to pkey")
        }

        let validationContext = EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
        defer { EVP_PKEY_CTX_free(validationContext) }
        // NOTE: Functions return -2 if the operation is not supported for the specific algorithm. Not an issue now.
        guard
            EVP_PKEY_param_check(validationContext) > 0,
            EVP_PKEY_public_check(validationContext) > 0
        else {
            throw OpenSSLError(name: "Error when validating the components of the key (bad data?)")
        }

        self.pkey = pkey
    }

    convenience init(x962: Data) throws {
        let group = Curve.group
        let length = x962.count
        guard length == (group.coordinateByteCount * 2) + 1 else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }
        try self.init(data: x962)
    }

    convenience init(compact: Data) throws {
        let group = Curve.group
        let length = compact.count
        guard length == group.coordinateByteCount + 1 else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }
        try self.init(data: compact)
    }

    init(pem _: Data) throws {
        throw OpenSSLError(name: "Not implemented")
    }

    deinit {
        EVP_PKEY_free(pkey)
    }

    // - NOTE: Unexpectedly, the output format of EVP_PKEY_todata() is POINT_CONVERSION_COMPRESSED(!) for the pub key
    //      and therefore cannot be used here. Work around for now is the usage of i2d_PublicKey().
    // see: https://github.com/openssl/openssl/issues/16595 and
    //      https://github.com/openssl/openssl/pull/16624
    func rawValue() throws -> Data {
        var buffer: UnsafeMutablePointer<UInt8>?
        let size = i2d_PublicKey(pkey, &buffer)
        guard size > 0, let safeBuffer = buffer else {
            throw OpenSSLError(name: "Unable to retrieve public key data")
        }
        return Data(bytesNoCopy: safeBuffer, count: Int(size), deallocator: .free)
    }

    func x962Value() throws -> Data {
        try rawValue()
    }

    func compactValue() throws -> Data {
        let dup = EVP_PKEY_dup(pkey)
        defer { EVP_PKEY_free(dup) }
        return try publicKeyCompactDataFromEvpPkey(dup)
    }
}

extension ECPublicKeyImpl {
    func verify(signature: ECDSASignature, digest: Digest) throws -> Bool {
        let success = try signature.derBytes.withUnsafeBytes { (signaturePtr: UnsafeRawBufferPointer) in
            try digest.withUnsafeBytes { (digestPtr: UnsafeRawBufferPointer) -> Int32 in
                let verificationContext = EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
                defer { EVP_PKEY_CTX_free(verificationContext) }
                guard EVP_PKEY_verify_init(verificationContext) == 1 else {
                    throw OpenSSLError(name: "Error setting up the signature verification context")
                }

                let result = EVP_PKEY_verify(
                    verificationContext,
                    signaturePtr.bindMemory(to: UInt8.self).baseAddress,
                    signaturePtr.count,
                    digestPtr.bindMemory(to: UInt8.self).baseAddress,
                    digestPtr.count
                )
                guard result >= 0 else {
                    throw OpenSSLError(name: "Serious error when verifying signature (e.g. bad data format, etc.)")
                }
                return result
            }
        }
        return success == 1
    }
}
