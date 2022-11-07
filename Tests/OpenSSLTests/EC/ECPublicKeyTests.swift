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

@testable import OpenSSL
import XCTest

final class ECPublicKeyTests: XCTestCase {
    func testBrainpoolP256r1PublicKey_InitData() throws {
        // given
        let pubKeyX962 =
            try Data(
                hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29" // swiftlint:disable:this line_length
            )

        // when
        let sut: ECPublicKey = try ECPublicKeyImpl<BrainpoolP256r1.Curve>(data: pubKeyX962)

        // then
        XCTAssertNotNil(sut)
        XCTAssertEqual(try sut.rawValue(), pubKeyX962)
        XCTAssertEqual(try sut.rawValue(), pubKeyX962)

        let expectedCompactKey = try Data(hex: "038634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB048888")
        XCTAssertEqual(try sut.compactValue(), expectedCompactKey)
    }

    func testBrainpoolP256r1PublicKey_InitCompact() throws {
        // given
        let compactKey = try Data(hex: "038634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB048888")

        // when
        let sut = try ECPublicKeyImpl<BrainpoolP256r1.Curve>(compact: compactKey)

        // then
        XCTAssertNotNil(sut)
        XCTAssertEqual(try sut.compactValue(), compactKey)

        let expectedPubKeyX962 =
            try Data(
                hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(try sut.rawValue(), expectedPubKeyX962)
        XCTAssertEqual(try sut.rawValue(), expectedPubKeyX962)
    }

    func testBrainpoolP256r1_ThrowsInitEmpty() throws {
        XCTAssertThrowsError(try ECPublicKeyImpl<BrainpoolP256r1.Curve>(x962: Data()))
        XCTAssertThrowsError(try ECPublicKeyImpl<BrainpoolP256r1.Curve>(compact: Data()))
    }
}
