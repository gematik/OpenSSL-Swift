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

import DataKit
@testable import OpenSSL
import XCTest

final class BrainpoolP256r1ExtPACETests: XCTestCase {
    func testPaceMapNonceBrainpoolP256r1() throws {
        // given
        let nonce = try Data(hex: "A44248628B8E8B94072EF3843C56E844")
        let ownPrivateKey1Raw = try Data(hex: "0D7DFFAC3558C4C3C075A0479F4C3A4864DBD8E686CDB154DD0BDD0BA7CE4D51")
        let ownPrivateKey1 = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(raw: ownPrivateKey1Raw)
        let peerKeyRaw =
            try Data(
                hex: "045CAC41779F548CBE714A08CBCEB40F616B5EFDD59DD3345802027DCB0C3FB02B20DC7A458B7744102DE98D350D4399FEC0F8CC5CCE50317A2CEE3CB418A4DA41" // swiftlint:disable:this line_length
            )
        let peerKey1 = try ECPublicKeyImpl<BrainpoolP256r1.Curve>(x962: peerKeyRaw)

        let ownPrivateKey2Raw = try Data(hex: "4C164B01D17B7C097B3640AF1EBCE0C88ED4B57738803872EEC3261EBB9A89E7")
        let keyPairGen = { try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(raw: ownPrivateKey2Raw) }

        // when
        let (ownPubKey2, keyPair2) = try ownPrivateKey1
            .paceMapNonce(nonce: nonce, peerKey1: peerKey1, keyPair: keyPairGen)

        // then
        let expectedPubKey2Raw =
            try Data(
                hex: "04A1D37688F62647E4B7CCEB64881142EEEC48FCF148BA2B518E3246166EF8495C81D0644A59DD6927E7492A4BD52926957450BEDED208B2E616D03D9504F9FE12" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(try ownPubKey2.rawValue(), expectedPubKey2Raw)
        XCTAssertEqual(try keyPair2.publicKey.rawValue(), try keyPairGen().publicKey.rawValue())
    }
}
