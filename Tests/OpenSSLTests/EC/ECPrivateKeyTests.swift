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

final class ECPrivateKeyTests: XCTestCase {
    func testGenerateKey() throws {
        // when
        let sut = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>()

        // then
        XCTAssertNotNil(sut)
        XCTAssertEqual(try sut.publicKey.x962Value().count, 65)
        XCTAssertEqual(try sut.publicKey.compactValue().count, 33)
    }

    func testBrainpoolP256r1_InitX962() throws {
        // given
        let keyX962 =
            try Data(
                hex: "040AB68E9435DCA456983930A62770461AC7F0C5E5DFC6D93032702E3213168248A21E1DF599CCD1832037101DEF5926069DE865EE48BBC3ED92DA273EFE935CC783456D98DEA3435C166385A4E644EBCA588E8A0AA7C811F51FCC736368630206" // swiftlint:disable:this line_length
            )

        // when
        let sut = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(x962: keyX962)

        // then
        XCTAssertNotNil(sut)

        let expectedRawPrivateKeyData =
            try Data(hex: "83456D98DEA3435C166385A4E644EBCA588E8A0AA7C811F51FCC736368630206")
        XCTAssertEqual(try sut.rawPrivateKeyData(), expectedRawPrivateKeyData)

        let expectCompactPublicKey = try Data(hex: "030AB68E9435DCA456983930A62770461AC7F0C5E5DFC6D93032702E3213168248")
        XCTAssertEqual(try sut.publicKey.compactValue(), expectCompactPublicKey)
    }

    func testBrainpoolP256r1_InitRaw() throws {
        // given
        let rawKey = try Data(hex: "5BBBA34D47502BD588ED680DFA2309CA375EB7A35DDBBD67CC7F8B6B687A1C1D")

        // when
        let sut = try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(raw: rawKey)

        // then
        XCTAssertNotNil(sut)

        let expectedPubKeyX962 =
            try Data(
                hex: "04754E548941E5CD073FED6D734578A484BE9F0BBFA1B6FA3168ED7FFB22878F0F9AEF9BBD932A020D8828367BD080A3E72B36C41EE40C87253F9B1B0BEB8371BF" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(try sut.publicKey.x962Value(), expectedPubKeyX962)
    }

    func testBrainpoolP256r1_ThrowsInitEmpty() throws {
        XCTAssertThrowsError(try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(x962: Data()))
        XCTAssertThrowsError(try ECPrivateKeyImpl<BrainpoolP256r1.Curve>(raw: Data()))
    }
}
