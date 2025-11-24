//
// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
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

            public func rawValue() throws -> Data {
                try pubKey.rawValue()
            }

            public func x962Value() throws -> Data {
                try pubKey.x962Value()
            }

            public func compactValue() throws -> Data {
                try pubKey.compactValue()
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

            public static func generateKey() throws -> PrivateKey {
                try Self(key: ECPrivateKeyImpl<BrainpoolP256r1.Curve>.generateKey())
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
