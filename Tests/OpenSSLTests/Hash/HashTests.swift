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
