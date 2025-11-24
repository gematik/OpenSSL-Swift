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

import CryptoKit
import Foundation

/// Hashing package
public enum Hash {}

/// SHA256 extension on Hash
public extension Hash { // swiftlint:disable:this no_extension_access_modifier
    /// SHA-256 Hash
    enum SHA256 {
        /// Hash the given data with SHA-256
        ///
        /// - Parameter data: hash input
        /// - Returns: SHA-256 hash
        public static func hash(data: Data) -> Data {
            Data(CryptoKit.SHA256.hash(data: data))
        }

        /// Hash the given string with SHA-256
        ///
        /// - Note: the String will be UTF-8 encoded before hashing it.
        /// - Parameter string: hash input
        /// - Returns: SHA-256 hash
        public static func hash(string: String) -> Data {
            guard let data = string.data(using: .utf8) else {
                preconditionFailure("String could not be utf8 encoded")
            }
            return hash(data: data)
        }
    }
}
