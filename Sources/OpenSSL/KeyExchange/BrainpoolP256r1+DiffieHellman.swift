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

/// Key exchange type for BrainpoolP256r1
public extension BrainpoolP256r1 { // swiftlint:disable:this no_extension_access_modifier
    /// KeyExchange types for the BrainpoolP256r1 Elliptic Curve
    enum KeyExchange {
        /// The BrainpoolP256r1 Public Key for ECDH KeyExchange
        public struct PublicKey: ECPublicKey {
            let pubKey: ECPublicKeyImpl<Curve>

            internal init(impl: ECPublicKeyImpl<Curve>) {
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
        }

        /// The BrainpoolP256r1 Private Key for ECDH KeyExchange
        public struct PrivateKey: ECPrivateKey, DiffieHellman, PACE {
            private let key: ECPrivateKeyImpl<Curve>

            init(key: ECPrivateKeyImpl<Curve>) {
                self.key = key
            }

            public init(raw: Data) throws {
                key = try ECPrivateKeyImpl(raw: raw)
            }

            public init(x962: Data) throws {
                key = try ECPrivateKeyImpl(x962: x962)
            }

            public var publicKey: KeyExchange.PublicKey {
                KeyExchange.PublicKey(impl: key.publicKey)
            }

            public func sharedSecret(with peerKey: KeyExchange.PublicKey) throws -> Data {
                try key.sharedSecret(with: peerKey.pubKey)
            }

            public func paceMapNonce(nonce: Data, peerKey1: PublicKey) throws -> (PublicKey, PrivateKey) {
                let (pub, priv) = try key.paceMapNonce(nonce: nonce, peerKey1: peerKey1.pubKey)
                return (PublicKey(impl: pub), PrivateKey(key: priv))
            }

            public static func generateKey() throws -> PrivateKey {
                try Self(key: ECPrivateKeyImpl.generateKey())
            }
        }

        /// Generate a key
        ///
        /// - Returns: the generated key pair
        /// - Throws: when no key pair could be generated
        public static func generateKey() throws -> PrivateKey {
            try KeyExchange.PrivateKey.generateKey()
        }
    }
}
