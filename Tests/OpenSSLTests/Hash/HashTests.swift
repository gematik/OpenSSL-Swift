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

@testable import OpenSSL
import XCTest

final class HashTests: XCTestCase {
    func testSha256() {
        let expectedHash = Data(
            [0xAF, 0xAC, 0xEC, 0xF8, 0x26, 0x4F, 0xDF, 0x05, 0x97, 0x75, 0xF3, 0x33, 0xD5, 0x0C, 0x00, 0x87,
             0x31, 0xDE, 0xCD, 0x80, 0xE9, 0x77, 0x38, 0x41, 0x4C, 0x4D, 0x4D, 0x1E, 0xD4, 0x02, 0x63, 0x19]
        )
        let hashable = "Hallotlghn"

        XCTAssertEqual(Hash.SHA256.hash(string: hashable), expectedHash)
    }
}
