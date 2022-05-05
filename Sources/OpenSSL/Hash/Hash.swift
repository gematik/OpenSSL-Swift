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
