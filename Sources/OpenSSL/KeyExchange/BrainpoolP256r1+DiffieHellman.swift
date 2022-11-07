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
