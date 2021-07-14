//
//  Copyright (c) 2021 gematik GmbH
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
    /// - Parameter compactRepresentable: whether the public key needs to be compact representable [e.g. compressed]
    /// - Returns: the generated key pair
    /// - Throws: when no key pair could be generated
    static func generateKey(compactRepresentable: Bool) throws -> Self
}

typealias EC_KEY = OpaquePointer

final class ECPrivateKeyImpl<Curve: ECCurve>: ECPrivateKey {
    private let key: EC_KEY

    /// Generate a key
    ///
    /// - Note: this initializer is not thread-safe due to the underlying openssl randomization not being thread-safe.
    ///
    /// [REQ:gemSpec_Krypt:GS-A_4368] Key generation delegation to OpenSSL according to the `ECCurve` group.
    /// [REQ:gemSpec_Krypt:GS-A_4361]
    /// [REQ:gemSpec_Krypt:GS-A_4357]
    ///
    /// - Parameter compactRepresentable: whether the public key needs to be compact representable [e.g. compressed]
    /// - Throws: when no key pair could be generated
    init(compactRepresentable: Bool) throws {
        let group = Curve.group
        key = try group.makeUnsafeOwnedECKey()

        var success = !compactRepresentable
        repeat {
            guard EC_KEY_generate_key(key) == 1 else {
                throw OpenSSLError(name: "Error while generating key")
            }

            success = try !compactRepresentable || isCompactRepresentable(
                group: group,
                publicKeyPoint: publicKey.point
            )
        } while !success
    }

    convenience init(x962: Data) throws {
        let group = Curve.group

        // Before we do anything, we validate that the raw representation has the right number of bytes.
        let length = x962.count
        guard length == (group.coordinateByteCount * 3) + 1 else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }

        // The x962 representation is 0x4 || x || y || k
        let offsetK = 1 + (2 * group.coordinateByteCount)
        let x962K = x962[offsetK...]
        try self.init(raw: x962K)
    }

    init(raw: Data) throws {
        let group = Curve.group

        // Before we do anything, we validate that the raw representation has the right number of bytes.
        // OpenSSL will quietly accept shorter byte counts, though it will reject longer ones.
        let length = raw.count
        guard length <= group.coordinateByteCount else {
            throw OpenSSLError(name: "incorrectParameterSize")
        }

        key = try group.makeUnsafeOwnedECKey()

        // The raw representation is just the bytes that make up k.
        // swiftlint:disable:next identifier_name
        let k = try BigNumber(bytes: raw)

        // Begin by setting the private key.
        try setPrivateKey(k)

        // Now calculate the public one and set it.
        let point = try EllipticCurvePoint(multiplying: k, on: group)
        try setPublicKey(point: point)
    }

    deinit {
        EC_KEY_free(key)
    }

    private func setPrivateKey(_ keyScalar: BigNumber) throws {
        try keyScalar.withUnsafeBignumPointer { bigNum in
            guard EC_KEY_set_private_key(key, bigNum) != 0 else {
                throw OpenSSLError(name: "Error initializing private key")
            }
        }
    }

    private func setPublicKey(point: EllipticCurvePoint) throws {
        try point.withPointPointer { ecPointer in
            guard EC_KEY_set_public_key(key, ecPointer) != 0 else {
                throw OpenSSLError(name: "Error setting public key for private key")
            }
        }
    }

    var publicKey: ECPublicKeyImpl<Curve> {
        guard let keyPtr = try? Curve.group.makeUnsafeOwnedECKey() else {
            fatalError("Unable to extract public key")
        }
        let pubKeyPoint = EC_KEY_get0_public_key(key)
        EC_KEY_set_public_key(keyPtr, pubKeyPoint)
        return ECPublicKeyImpl(pubKey: keyPtr)
    }

    func multiply(with point: EllipticCurvePoint) throws -> EllipticCurvePoint {
        /* Extract the private key material, then try a multiplication with the given point */
        var buffer: UnsafeMutablePointer<UInt8>?
        let size = EC_KEY_priv2buf(key, &buffer)
        guard size > 0, let safeBuffer = buffer else {
            throw OpenSSLError(name: "Unable to perform OpenSSL buffer operation")
        }
        let rawValue = Data(bytesNoCopy: safeBuffer, count: size, deallocator: .free)
        let privateKeyNum = try BigNumber(bytes: rawValue)
        return try EllipticCurvePoint(multiplying: privateKeyNum, with: point, on: Curve.group)
    }

    func sign(digest: Digest) throws -> ECDSASignature {
        try digest.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            guard let address = ptr.bindMemory(to: UInt8.self).baseAddress,
                  let signature = ECDSA_do_sign(address, CInt(ptr.count), key) else {
                throw OpenSSLError(name: "Unable to sign a digest")
            }
            return ECDSASignature(owningNoCopy: signature)
        }
    }

    class func generateKey(compactRepresentable flag: Bool) throws -> ECPrivateKeyImpl<Curve> {
        try ECPrivateKeyImpl(compactRepresentable: flag)
    }
}

extension ECPrivateKeyImpl: DiffieHellman {
    public func sharedSecret(with peerKey: ECPublicKeyImpl<Curve>) throws -> Data {
        /* Calculate the size of the buffer for the shared secret */
        let fieldSize = EC_GROUP_get_degree(EC_KEY_get0_group(key))
        let secretLength = Int((fieldSize + 7) / 8)

        /* Allocate the memory for the shared secret */
        var secretBuffer = [UInt8](repeating: 0x0, count: secretLength)
        let derivedSecretLength = ECDH_compute_key(
            &secretBuffer,
            secretLength,
            EC_KEY_get0_public_key(peerKey.pubKey),
            key,
            nil
        )

        guard derivedSecretLength == secretLength else {
            throw OpenSSLError(name: "Could not derive shared secret")
        }

        return Data(secretBuffer)
    }
}

extension ECPrivateKeyImpl: DigestSigner {}

/// In a number of places we need to know if an EC key is compact representable. This function implements that check.
///
/// The check is defined in https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#rfc.section.4.2.1. Specifically,
/// a point is compact representable if its y coordinate is the smaller of min(y, p-y) where p is the order of the
/// prime field.
@usableFromInline
func isCompactRepresentable(group: OpenSSLECGroup, publicKeyPoint: EllipticCurvePoint) throws -> Bool {
    let (_, y) = try publicKeyPoint.affineCoordinates(group: group) // swiftlint:disable:this identifier_name
    let (fieldP, _, _) = group.weierstrassCoefficients
    let context = try FiniteBigNumberFieldArithmeticContext(fieldSize: fieldP)
    guard let newY = context.subtract(y, from: group.order) else {
        return false
    }

    // The point is compact representable if y is less than or equal to newY.
    return y <= newY
}
