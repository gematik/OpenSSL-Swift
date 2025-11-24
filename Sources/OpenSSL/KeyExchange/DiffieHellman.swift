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

@_implementationOnly import COpenSSL
import Foundation

/// DiffieHellman sharedSecret protocol
public protocol DiffieHellman {
    /// The associated PublicKey type
    associatedtype PublicKey

    /// Compute a shared secret using the given public key
    ///
    /// - Note: This protocol assumes the implementation has access [or represents] the private or
    ///         pre-shared secret information.
    ///
    /// - Parameter peerKey: the public key material to derive a shared secret in conjunction
    ///                         with its own private information.
    /// - Returns: The shared secret in raw bytes
    /// - Throws: `OpenSSLError` in case this operation was not supported
    func sharedSecret(with peerKey: PublicKey) throws -> Data
}
