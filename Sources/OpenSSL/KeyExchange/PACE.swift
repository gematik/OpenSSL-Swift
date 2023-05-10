//
// Copyright 2016, European Community
// Copyright 2023, gematik GmbH

// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.

// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12

// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.

// See the Licence for the specific language governing permissions and limitations under the Licence.
//

@_implementationOnly import COpenSSL
import Foundation

/// PACE (Password Authenticated Connection Establishment) protocol
public protocol PACE: DiffieHellman {
    /// The associated own key PrivateKey type
    associatedtype PrivateKey

    /// The PACE protocol sets up a SecureMessaging channel with strong session keys based on a shared password,
    /// possibly of low entropy.
    /// see: BSI TR-03110 https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html
    ///
    /// - Parameters:
    ///   - nonce: Plain nonce queried from the peer entity
    ///   - peerKey1: First ephemeral public key received from the peer entity
    /// - Returns: Derived own `PublicKey` and the second (generated) `PrivateKey` (pair)
    /// - Throws: when no ephemeral public key could be generated
    func paceMapNonce(nonce: Data, peerKey1: PublicKey) throws -> (PublicKey, PrivateKey)
}

/// This implementation follows PACE protocol conformance as specified in gemSpec_COS_V3.11.0 (N085.064)
/// for establishing a secure channel communication with German health cards.
///
/// First calculate an ephemeral generator g~ = nonce * g + ownKey1.priv * peerKey1
/// Then perform an ECDH key agreement using the new group generator g~ together with a second private key (pair).
/// Return the derived second own public key and the second (generated) private key (pair).
extension ECPrivateKeyImpl: PACE {
    public func paceMapNonce(
        nonce: Data,
        peerKey1: ECPublicKeyImpl<Curve>
    ) throws -> (ECPublicKeyImpl<Curve>, ECPrivateKeyImpl) {
        try paceMapNonce(nonce: nonce, peerKey1: peerKey1) {
            try Self.generateKey()
        }
    }

    func paceMapNonce(
        nonce: Data,
        peerKey1: ECPublicKeyImpl<Curve>,
        keyPair generator: () throws -> PrivateKey
    ) throws -> (ECPublicKeyImpl<Curve>, ECPrivateKeyImpl) {
        let gTilde = try paceMapNoncePart1(nonce: nonce, peerKey1: peerKey1)
        return try paceMapNoncePart2(gTilde: gTilde, keyPair: generator)
    }

    // Part 1:
    // Calculate ephemeral shared secret Point g~ = nonce * g + ownKey1.priv * peerKey1
    private func paceMapNoncePart1(nonce: Data, peerKey1: ECPublicKeyImpl<Curve>) throws -> EllipticCurvePoint<Curve> {
        // summand1 = nonce * G
        let nonce = try BigNumber(bytes: nonce)
        let summand1 = try EllipticCurvePoint<Curve>(multiplyWithBasePoint: nonce)

        // summand2 = ownKey1.priv * peerKey1
        let summand2 = try multiply(with: EllipticCurvePoint<Curve>(raw: peerKey1.rawValue()))

        // g~ = summand1 + summand2
        return try summand1.add(summand2)
    }

    // Part2:
    // Generate a second private key (pair) and return derived ownPubKey2 = privKey2 * g~ and keyPair2
    private func paceMapNoncePart2(
        gTilde: EllipticCurvePoint<Curve>,
        keyPair generator: () throws -> PrivateKey
    ) throws -> (ECPublicKeyImpl<Curve>, ECPrivateKeyImpl) {
        let privateKey2 = try generator()
        let ownPubKeyPoint2: EllipticCurvePoint = try privateKey2.multiply(with: gTilde)

        let ownPubKeyX962 = try ownPubKeyPoint2.export(pointConversion: .uncompressed)
        let ownPubKey = try ECPublicKeyImpl<Curve>(x962: ownPubKeyX962)

        return (ownPubKey, privateKey2)
    }
}
