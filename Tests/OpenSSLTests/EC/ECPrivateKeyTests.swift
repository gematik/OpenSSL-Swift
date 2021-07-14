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

final class ECPrivateKeyTests: XCTestCase {
    func testBrainpoolP256r1InitX962() throws {
        let compactPublicKey = try Data(hex: "030AB68E9435DCA456983930A62770461AC7F0C5E5DFC6D93032702E3213168248")
        let keyX962 =
            try Data(
                hex: "040AB68E9435DCA456983930A62770461AC7F0C5E5DFC6D93032702E3213168248A21E1DF599CCD1832037101DEF5926069DE865EE48BBC3ED92DA273EFE935CC783456D98DEA3435C166385A4E644EBCA588E8A0AA7C811F51FCC736368630206" // swiftlint:disable:this line_length
            )

        let privateKey = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(x962: keyX962)
        XCTAssertNotNil(privateKey)
        let publicKey = privateKey.publicKey
        XCTAssertEqual(publicKey.compactValue, compactPublicKey)
    }

    func testBrainpoolP256r1InitRaw() throws {
        let rawKey = try Data(hex: "5BBBA34D47502BD588ED680DFA2309CA375EB7A35DDBBD67CC7F8B6B687A1C1D")
        let pubKeyX962 =
            try Data(
                hex: "04754E548941E5CD073FED6D734578A484BE9F0BBFA1B6FA3168ED7FFB22878F0F9AEF9BBD932A020D8828367BD080A3E72B36C41EE40C87253F9B1B0BEB8371BF" // swiftlint:disable:this line_length
            )
        let privateKey = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(raw: rawKey)
        XCTAssertNotNil(privateKey)
        let publicKey = privateKey.publicKey
        XCTAssertEqual(publicKey.x962Value, pubKeyX962)
    }
}
