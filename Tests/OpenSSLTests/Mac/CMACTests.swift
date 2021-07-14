//
//  Copyright (c) 2021 gematik GmbH
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

import DataKit
@testable import OpenSSL
import XCTest

final class CMACTests: XCTestCase {
    func testAes128CbcCmacEmptyMessage() throws {
        // given
        let key = try Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
        let message = try Data(hex: "")

        // when
        let cmac = try CMAC.aes128cbc(key: key, data: message)

        // then
        let expectedCmac = try Data(hex: "bb1d6929e95937287fa37d129b756746")
        XCTAssertEqual(cmac, expectedCmac)
    }

    func testAes128CbcCmacMessageLength16() throws {
        // given
        let key = try Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
        let message = try Data(hex: "6bc1bee22e409f96e93d7e117393172a")

        // when
        let cmac = try CMAC.aes128cbc(key: key, data: message)

        // then
        let expectedCmac = try Data(hex: "070a16b46b4d4144f79bdd9dd04a287c")
        XCTAssertEqual(cmac, expectedCmac)
    }

    func testAes128CbcCmacMessageLength64() throws {
        // given
        let key = try Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
        let message =
            try Data(
                hex:
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710" // swiftlint:disable:this line_length
            )

        // when
        let cmac = try CMAC.aes128cbc(key: key, data: message)

        // then
        let expectedCmac = try Data(hex: "51f0bebf7e3b9d92fc49741779363cfe")
        XCTAssertEqual(cmac, expectedCmac)
    }

    func testAes128CbcCmacInvalidKey() throws {
        // given
        let message = try Data(hex: "")

        // when
        let invalidKeyShort = try Data(hex: "2b7e151628aed2a6abf7158809cf4f")
        let invalidKeyLong = try Data(hex: "2b7e151628aed2a6abf7158809cf4f3c00")

        // then
        XCTAssertThrowsError(try CMAC.aes128cbc(key: invalidKeyShort, data: message))
        XCTAssertThrowsError(try CMAC.aes128cbc(key: invalidKeyLong, data: message))
    }
}
