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

import Foundation

/// Validation and signing with BrainpoolP256r1 for ECDSA
public extension BrainpoolP256r1 { // swiftlint:disable:this no_extension_access_modifier
    /// Verify signatures for the BrainpoolP256r1 Elliptic Curve
    enum Verify {
        /// The BrainpoolP256r1 Public Key for ECDSA verification
        public struct PublicKey: ECPublicKey, SignatureVerifier {
            let pubKey: ECPublicKeyImpl<BrainpoolP256r1.Curve>

            internal init(impl: ECPublicKeyImpl<BrainpoolP256r1.Curve>) {
                pubKey = impl
            }

            public init(compact: Data) throws {
                pubKey = try ECPublicKeyImpl(compact: compact)
            }

            public init(x962: Data) throws {
                pubKey = try ECPublicKeyImpl(x962: x962)
            }

            public var rawValue: Data {
                pubKey.rawValue
            }

            public var x962Value: Data {
                pubKey.x962Value
            }

            public var compactValue: Data? {
                pubKey.compactValue
            }

            public func verify(signature: Signature, message: Data) throws -> Bool {
                try pubKey.verify(
                    signature: ECDSASignature(signature: signature),
                    digest: Hash.SHA256.hash(data: message)
                )
            }
        }

        /// The BrainpoolP256r1 Private Key for ECDSA signing
        public struct PrivateKey: ECPrivateKey, Signer {
            private let key: ECPrivateKeyImpl<BrainpoolP256r1.Curve>

            init(key: ECPrivateKeyImpl<BrainpoolP256r1.Curve>) {
                self.key = key
            }

            public init(raw: Data) throws {
                key = try ECPrivateKeyImpl(raw: raw)
            }

            public init(x962: Data) throws {
                key = try ECPrivateKeyImpl(x962: x962)
            }

            public var publicKey: Verify.PublicKey {
                Verify.PublicKey(impl: key.publicKey)
            }

            public func sign(message: Data) throws -> Signature {
                try Signature(signature: key.sign(digest: Hash.SHA256.hash(data: message)))
            }

            public static func generateKey(compactRepresentable flag: Bool) throws -> PrivateKey {
                try Self(key: ECPrivateKeyImpl<BrainpoolP256r1.Curve>.generateKey(compactRepresentable: flag))
            }
        }

        public struct Signature: ECSignature {
            private let signature: ECDSASignature

            internal init(signature: ECDSASignature) {
                self.signature = signature
            }

            public init(rawRepresentation: Data) throws {
                signature = try ECDSASignature(rawRepresentation: rawRepresentation)
            }

            public init(derRepresentation: Data) throws {
                signature = try ECDSASignature(derRepresentation: derRepresentation)
            }

            public var derRepresentation: Data {
                signature.derBytes
            }

            public var rawRepresentation: Data {
                signature.rawBytes
            }
        }
    }
}
