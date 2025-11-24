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

/// Typealias for Digest
public typealias Digest = Data

/// Protocol for message signer
public protocol Signer {
    /// Type signature type
    associatedtype Signature
    /// Sign a message
    ///
    /// - Parameter message: message to hash and then sign
    /// - Returns: the signature
    /// - Throws: `OpenSSLError`
    func sign(message: Data) throws -> Signature
}

/// Protocol for digest signers
public protocol DigestSigner {
    /// Signature type
    associatedtype Signature
    /// Sign a digest
    ///
    /// - Parameter digest: the hash to be signed/encrypted
    /// - Returns: the signature
    /// - Throws: `OpenSSLError`
    func sign(digest: Digest) throws -> Signature
}

/// Protocol for message verifiers
public protocol SignatureVerifier {
    /// The signature type
    associatedtype Signature
    /// Verify a signature for the given message
    ///
    /// - Note: message will be hashed by the function before verification
    ///
    /// - Parameters:
    ///   - signature: the signature for the given message
    ///   - message: the message to verify
    /// - Returns: true when the message is signed with given signature
    /// - Throws: `OpenSSLError`
    func verify(signature: Signature, message: Data) throws -> Bool
}

/// Protocol for EC Signature types
public protocol ECSignature {
    /// Initialize from rawRepresentation
    ///
    /// - Parameter rawRepresentation: raw signature value
    /// - Throws: `OpenSSLError`
    init(rawRepresentation: Data) throws
    /// Initialize from DER encoded data
    ///
    /// - Parameter derRepresentation: ASN.1 DER encoded signature
    /// - Throws: `OpenSSLError`
    init(derRepresentation: Data) throws
    /// ASN.1 DER encoded signature
    var derRepresentation: Data { get }
    /// Raw signature data
    var rawRepresentation: Data { get }
}
