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
    var rawValue: Data { get }
    /// The raw EC Public Key representation using ANSI X9.62 standard [04 || X || Y]. (uncompressed)
    var x962Value: Data { get }
    /// The raw EC Public Key compressed representation
    var compactValue: Data? { get }
}

final class ECPublicKeyImpl<Curve: ECCurve>: ECPublicKey {
    let pubKey: EC_KEY

    /// Owning Non-copying initializer for EC Public Key
    ///
    /// - Parameter pubKey: pointer to the EC_KEY to own and manage
    internal init(pubKey: EC_KEY) {
        self.pubKey = pubKey
    }

    private init(data: Data, curve group: OpenSSLECGroup) throws {
        pubKey = try group.makeUnsafeOwnedECKey()
        let point = EC_POINT_new(group.curve)
        let resultCode = try data.withUnsafeBytes { buffer -> CInt in
            guard let bufferPointer = buffer.bindMemory(to: UInt8.self).baseAddress else {
                throw OpenSSLError(name: "Public key data unavailable")
            }
            return EC_POINT_oct2point(group.curve, point, bufferPointer, buffer.count, nil)
        }
        guard resultCode == 1 else {
            throw OpenSSLError(name: "incorrect public key encoding")
        }
        EC_KEY_set_public_key(pubKey, point)
    }

    convenience init(x962: Data) throws {
        let group = Curve.group
        let length = x962.count
        guard length == (group.coordinateByteCount * 2) + 1 else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }
        try self.init(data: x962, curve: group)
    }

    convenience init(compact: Data) throws {
        let group = Curve.group
        let length = compact.count
        guard length == group.coordinateByteCount + 1 else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }
        try self.init(data: compact, curve: group)
    }

    init(pem _: Data) throws {
        throw OpenSSLError(name: "Not implemented")
    }

    deinit {
        EC_KEY_free(pubKey)
    }

    var rawValue: Data {
        exportKey(using: POINT_CONVERSION_UNCOMPRESSED) ?? Data()
    }

    var x962Value: Data {
        rawValue
    }

    var compactValue: Data? {
        exportKey(using: POINT_CONVERSION_COMPRESSED)
    }

    private func exportKey(using compression: point_conversion_form_t) -> Data? {
        var buffer: UnsafeMutablePointer<UInt8>?
        let size = EC_KEY_key2buf(pubKey, compression, &buffer, nil)
        guard size > 0, let safeBuffer = buffer else {
            return nil
        }
        return Data(bytesNoCopy: safeBuffer, count: size, deallocator: .free)
    }

    var point: EllipticCurvePoint {
        let pubKeyPtr = EC_KEY_get0_public_key(pubKey)
        guard let pointPtr = Curve.group.withUnsafeGroupPointer({ groupPtr in
            EC_POINT_dup(pubKeyPtr, groupPtr)
        }) else {
            preconditionFailure("Public key has no point value! Malformed initialization?")
        }
        return EllipticCurvePoint(point: pointPtr)
    }
}

extension ECPublicKeyImpl {
    func verify(signature: ECDSASignature, digest: Digest) throws -> Bool {
        let success = signature.withUnsafeSignaturePointer { signaturePtr in
            digest.withUnsafeBytes { (digestPtr: UnsafeRawBufferPointer) in
                /** Verifies that the supplied signature is a valid ECDSA
                 *  signature of the supplied hash value using the supplied public key.
                 *  \param  dgst      pointer to the hash value
                 *  \param  dgst_len  length of the hash value
                 *  \param  sig       ECDSA_SIG structure
                 *  \param  eckey     EC_KEY object containing a public EC key
                 *  \return 1 if the signature is valid, 0 if the signature is invalid
                 *          and -1 on error
                 */
                ECDSA_do_verify(
                    digestPtr.bindMemory(to: UInt8.self).baseAddress,
                    CInt(digestPtr.count),
                    signaturePtr,
                    self.pubKey
                )
            }
        }

        return success == 1
    }
}
