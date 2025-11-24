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
@testable import OpenSSL
import XCTest

final class ECDSASignatureTest: XCTestCase {
    func testECDSASignatureRawRepresentation() {
        let rawSignature =
            try! Data(
                hex: "1ead1d24d3966a388bd64c31ce1a9ba86393767ab8b937302a26f0f68049c024607ac0358c5ace66bc6c8c5e3eeead5a7456d0a8e046c1642e3e68e6957e84a5"
            )
        let signature = try! ECDSASignature(rawRepresentation: rawSignature)
        XCTAssertEqual(rawSignature, signature.rawBytes)
    }

    func testECDSASignatureDER() {
        let derSignature = try! Data(
            hex: "3046022100A893CCFB5530AEDB9173378B3AC912DD765CFFA5CA1B249B4821DB7E82F60DEA0221009842AC2C38E85A60E6A85824076BD484BDC377DBB31BC293D137D7CB8D5CAB05"
        )
        let signature = try! ECDSASignature(derRepresentation: derSignature)
        let expectedRaw = try! Data(hex:
            "A893CCFB5530AEDB9173378B3AC912DD765CFFA5CA1B249B4821DB7E82F60DEA9842AC2C38E85A60E6A85824076BD484BDC377DBB31BC293D137D7CB8D5CAB05")
        XCTAssertEqual(expectedRaw, signature.rawBytes)
        XCTAssertEqual(derSignature, signature.derBytes)
    }
}
