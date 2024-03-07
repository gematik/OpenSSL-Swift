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

final class BrainpoolP256r1ExtDiffieHellmanTests: XCTestCase {
    func testDeriveSharedSecretFromBrainpoolP256r1() throws {
        let pubKeyRaw =
            try Data(
                hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29" // swiftlint:disable:this line_length
            )
        let privateKeyRaw = try Data(hex: "83456D98DEA3435C166385A4E644EBCA588E8A0AA7C811F51FCC736368630206")
        let expectedSharedSecret = try Data(hex: "29AAA0349B1A3AA99501EA0D087E05F0E7A51C356693BE5BA010CA615C7BB5FD")
        let pubKey = try BrainpoolP256r1.KeyExchange.PublicKey(x962: pubKeyRaw)
        let privateKey = try BrainpoolP256r1.KeyExchange.PrivateKey(raw: privateKeyRaw)
        let sharedSecretData = try privateKey.sharedSecret(with: pubKey)

        XCTAssertNotEqual(try privateKey.publicKey.rawValue(), try pubKey.rawValue())
        XCTAssertEqual(expectedSharedSecret, sharedSecretData)
    }

    func testDeriveSharedSecretFromBrainpoolP256r1_2() throws {
        let pubKeyRaw =
            try Data(
                hex: "048634212830DAD457CA05305E6687134166B9C21A65FFEBF555F4E75DFB04888866E4B6843624CBDA43C97EA89968BC41FD53576F82C03EFA7D601B9FACAC2B29" // swiftlint:disable:this line_length
            )
        let privateKeyRaw = try Data(hex: "5bbba34d47502bd588ed680dfa2309ca375eb7a35ddbbd67cc7f8b6b687a1c1d")
        let expectedSharedSecret = try Data(hex: "9656c2b4b3da81d0385f6a1ee60e93b91828fd90231c923d53ce7bbbcd58ceaa")
        let pubKey = try BrainpoolP256r1.KeyExchange.PublicKey(x962: pubKeyRaw)
        let privateKey = try BrainpoolP256r1.KeyExchange.PrivateKey(raw: privateKeyRaw)
        let sharedSecretData = try privateKey.sharedSecret(with: pubKey)

        XCTAssertNotEqual(try privateKey.publicKey.rawValue(), try pubKey.rawValue())
        XCTAssertEqual(expectedSharedSecret, sharedSecretData)
    }
}
