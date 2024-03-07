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
