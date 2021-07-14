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

@testable import OpenSSL
import XCTest

final class ECPublicKeyTests: XCTestCase {
    func testBrainpoolP256r1InitX962() throws {
        let pubKeyX962 =
            try Data(
                hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29" // swiftlint:disable:this line_length
            )

        let pubKey: ECPublicKey = try ECPublicKeyImpl<BrainpoolP256r1.Curve>(x962: pubKeyX962)
        XCTAssertNotNil(pubKey)
        XCTAssertEqual(pubKeyX962, pubKey.rawValue)
        XCTAssertEqual(pubKeyX962, pubKey.x962Value)
        let compactKey = try Data(hex: "038634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB048888")
        XCTAssertEqual(compactKey, pubKey.compactValue)
    }

    func testBrainpoolP256r1InitCompact() throws {
        let compactKey = try Data(hex: "038634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB048888")
        let pubKeyX962 =
            try Data(
                hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29" // swiftlint:disable:this line_length
            )

        let pubKey: ECPublicKey = try ECPublicKeyImpl<BrainpoolP256r1.Curve>(compact: compactKey)
        XCTAssertNotNil(pubKey)
        XCTAssertEqual(pubKeyX962, pubKey.rawValue)
        XCTAssertEqual(pubKeyX962, pubKey.x962Value)
        XCTAssertEqual(compactKey, pubKey.compactValue)
    }
}
