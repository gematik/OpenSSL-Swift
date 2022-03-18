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
import Foundation
@testable import OpenSSL
import XCTest

final class BrainpoolP256r1ExtECDSATests: XCTestCase {
    func testVerifyBP256r1Signature() {
        // swiftlint:disable line_length
        let pubkeyraw =
            try! Data(
                hex: "049650ac6d4d5b1201de4cffe99db3a2396426a377bc95d9dc466727a2574d7c39643159e578f05a6b607e89afdd5395eeacc8e72714489cac3160c4bb79aa45c6"
            )
        let pubKey = try! BrainpoolP256r1.Verify.PublicKey(x962: pubkeyraw)
        let message =
            "eyJhbGciOiJCUDI1NlIxIiwieDVjIjpbIk1JSUNzVENDQWxpZ0F3SUJBZ0lIQTYxSTVBQ1VqVEFLQmdncWhrak9QUVFEQWpDQmhERUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhNakF3QmdOVkJBc01LVXR2YlhCdmJtVnVkR1Z1TFVOQklHUmxjaUJVWld4bGJXRjBhV3RwYm1aeVlYTjBjblZyZEhWeU1TQXdIZ1lEVlFRRERCZEhSVTB1UzA5TlVDMURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHlNREE0TURRd01EQXdNREJhRncweU5UQTRNRFF5TXpVNU5UbGFNRWt4Q3pBSkJnTlZCQVlUQWtSRk1TWXdKQVlEVlFRS0RCMW5aVzFoZEdscklGUkZVMVF0VDA1TVdTQXRJRTVQVkMxV1FVeEpSREVTTUJBR0ExVUVBd3dKU1VSUUlGTnBaeUF4TUZvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUhBMElBQkpaUXJHMU5XeElCM2t6LzZaMnpvamxrSnFOM3ZKWFozRVpuSjZKWFRYdzVaREZaNVhqd1dtdGdmb212M1ZPVjdxekk1eWNVU0p5c01XREV1M21xUmNhamdlMHdnZW93SFFZRFZSME9CQllFRko4RFZMQVpXVCtCbG9qVEQ0TVQvTmErRVM4WU1EZ0dDQ3NHQVFVRkJ3RUJCQ3d3S2pBb0JnZ3JCZ0VGQlFjd0FZWWNhSFIwY0RvdkwyVm9ZMkV1WjJWdFlYUnBheTVrWlM5dlkzTndMekFNQmdOVkhSTUJBZjhFQWpBQU1DRUdBMVVkSUFRYU1CZ3dDZ1lJS29JVUFFd0VnVXN3Q2dZSUtvSVVBRXdFZ1NNd0h3WURWUjBqQkJnd0ZvQVVLUEQ0NXFuSWQ4eERSZHVhcnRjNmc2d09ENmd3TFFZRkt5UUlBd01FSkRBaU1DQXdIakFjTUJvd0RBd0tTVVJRTFVScFpXNXpkREFLQmdncWdoUUFUQVNDQkRBT0JnTlZIUThCQWY4RUJBTUNCNEF3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnVkJQaEF3eVg4SEFWSDBPMGIzK1ZhenBCQVdrUU5qa0VWUmt2K0VZWDFlOENJRmRuNE8rbml2TStYVmk5eGlLSzRkVzFSN01EMzM0T3BPUFRGamVFaElWViJdfQ.eyJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTgwL2F1dGhvcml6YXRpb24iLCJ0b2tlbl9lbmRwb2ludCI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC90b2tlbiIsImlzc3VlciI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC9hdXRoL3JlYWxtcy9pZHAiLCJqd2tzX3VyaSI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC9qd2tzIiwicHVrX3VyaV9hdXRoIjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTgwL2F1dGhLZXkvandrcy5qc29uIiwicHVrX3VyaV90b2tlbiI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC90b2tlbktleS9qd2tzLmpzb24iLCJwdWtfdXJpX2Rpc2MiOiJodHRwOi8vZ3N0b3BkaDIudG9wLmxvY2FsOjg1ODAvZGlzY0tleS9qd2tzLmpzb24iLCJzdWJqZWN0X3R5cGVzX3N1cHBvcnRlZCI6WyJwYWlyd2lzZSJdLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkJQMjU2UjEiXSwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbImNvZGUiXSwic2NvcGVzX3N1cHBvcnRlZCI6WyJvcGVuaWQiLCJlLXJlemVwdCJdLCJyZXNwb25zZV9tb2Rlc19zdXBwb3J0ZWQiOlsicXVlcnkiXSwiZ3JhbnRfdHlwZXNfc3VwcG9ydGVkIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJhY3JfdmFsdWVzX3N1cHBvcnRlZCI6WyJ1cm46ZWlkYXM6bG9hOmhpZ2giXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJub25lIl19"

        let rawSignature =
            try! Data(
                hex: "1ead1d24d3966a388bd64c31ce1a9ba86393767ab8b937302a26f0f68049c024607ac0358c5ace66bc6c8c5e3eeead5a7456d0a8e046c1642e3e68e6957e84a5"
            )
        let rawSignature1 =
            try! Data(
                hex: "16ad3a9445293ec8c5fedec64f431a1c20ef6a1ec13a5b517124cac92191474977909364a96c22369b8806300f666735e4ea7eff04af73d8e28ffc136f32c8e9"
            )
        let rawSignature2 =
            try! Data(
                hex: "3b466e3e5fccf62587d86d46d80ce328dab44fbb3c41da44b631be88a863379871270106f26a1e6f1fd4b786522d869a7a15c306a8c41fd60ea25ce950864c64"
            )
        let invalidRawSignature =
            try! Data(
                hex: "b3466e3e5fccf62587d86d46d80ce328dab44fbb3c41da44b631be88a863379871270106f26a1e6f1fd4b786522d869a7a15c306a8c41fd60ea25ce950864c64"
            )
        // swiftlint:enable line_length

        let signature = try! BrainpoolP256r1.Verify.Signature(rawRepresentation: rawSignature)
        let signature1 = try! BrainpoolP256r1.Verify.Signature(rawRepresentation: rawSignature1)
        let signature2 = try! BrainpoolP256r1.Verify.Signature(rawRepresentation: rawSignature2)
        let invalidSignature = try! BrainpoolP256r1.Verify.Signature(rawRepresentation: invalidRawSignature)

        XCTAssertTrue(try pubKey.verify(signature: signature, message: message.data(using: .utf8)!))
        XCTAssertTrue(try pubKey.verify(signature: signature1, message: message.data(using: .utf8)!))
        XCTAssertTrue(try pubKey.verify(signature: signature2, message: message.data(using: .utf8)!))
        XCTAssertFalse(try pubKey.verify(signature: invalidSignature, message: message.data(using: .utf8)!))
        XCTAssertFalse(try pubKey.verify(signature: signature, message: "wrong message".data(using: .utf8)!))
    }

    func testSignBP256r1() {
        let key = try! BrainpoolP256r1.Verify.PrivateKey.generateKey(compactRepresentable: true)
        let message =
            "eyJhbGciOiJCUDI1NlIxIiwieDVjIjpbIk1JSUNzVENDQWxpZ0F3SUJBZ0lIQTYxSTVBQ1VqVEFLQmdncWhrak9QUVFEQWpDQmhERUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhNakF3QmdOVkJBc01LVXR2YlhCdmJtVnVkR1Z1TFVOQklHUmxjaUJVWld4bGJXRjBhV3RwYm1aeVlYTjBjblZyZEhWeU1TQXdIZ1lEVlFRRERCZEhSVTB1UzA5TlVDMURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHlNREE0TURRd01EQXdNREJhRncweU5UQTRNRFF5TXpVNU5UbGFNRWt4Q3pBSkJnTlZCQVlUQWtSRk1TWXdKQVlEVlFRS0RCMW5aVzFoZEdscklGUkZVMVF0VDA1TVdTQXRJRTVQVkMxV1FVeEpSREVTTUJBR0ExVUVBd3dKU1VSUUlGTnBaeUF4TUZvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUhBMElBQkpaUXJHMU5XeElCM2t6LzZaMnpvamxrSnFOM3ZKWFozRVpuSjZKWFRYdzVaREZaNVhqd1dtdGdmb212M1ZPVjdxekk1eWNVU0p5c01XREV1M21xUmNhamdlMHdnZW93SFFZRFZSME9CQllFRko4RFZMQVpXVCtCbG9qVEQ0TVQvTmErRVM4WU1EZ0dDQ3NHQVFVRkJ3RUJCQ3d3S2pBb0JnZ3JCZ0VGQlFjd0FZWWNhSFIwY0RvdkwyVm9ZMkV1WjJWdFlYUnBheTVrWlM5dlkzTndMekFNQmdOVkhSTUJBZjhFQWpBQU1DRUdBMVVkSUFRYU1CZ3dDZ1lJS29JVUFFd0VnVXN3Q2dZSUtvSVVBRXdFZ1NNd0h3WURWUjBqQkJnd0ZvQVVLUEQ0NXFuSWQ4eERSZHVhcnRjNmc2d09ENmd3TFFZRkt5UUlBd01FSkRBaU1DQXdIakFjTUJvd0RBd0tTVVJRTFVScFpXNXpkREFLQmdncWdoUUFUQVNDQkRBT0JnTlZIUThCQWY4RUJBTUNCNEF3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnVkJQaEF3eVg4SEFWSDBPMGIzK1ZhenBCQVdrUU5qa0VWUmt2K0VZWDFlOENJRmRuNE8rbml2TStYVmk5eGlLSzRkVzFSN01EMzM0T3BPUFRGamVFaElWViJdfQ.eyJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTgwL2F1dGhvcml6YXRpb24iLCJ0b2tlbl9lbmRwb2ludCI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC90b2tlbiIsImlzc3VlciI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC9hdXRoL3JlYWxtcy9pZHAiLCJqd2tzX3VyaSI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC9qd2tzIiwicHVrX3VyaV9hdXRoIjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTgwL2F1dGhLZXkvandrcy5qc29uIiwicHVrX3VyaV90b2tlbiI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU4MC90b2tlbktleS9qd2tzLmpzb24iLCJwdWtfdXJpX2Rpc2MiOiJodHRwOi8vZ3N0b3BkaDIudG9wLmxvY2FsOjg1ODAvZGlzY0tleS9qd2tzLmpzb24iLCJzdWJqZWN0X3R5cGVzX3N1cHBvcnRlZCI6WyJwYWlyd2lzZSJdLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkJQMjU2UjEiXSwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbImNvZGUiXSwic2NvcGVzX3N1cHBvcnRlZCI6WyJvcGVuaWQiLCJlLXJlemVwdCJdLCJyZXNwb25zZV9tb2Rlc19zdXBwb3J0ZWQiOlsicXVlcnkiXSwiZ3JhbnRfdHlwZXNfc3VwcG9ydGVkIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJhY3JfdmFsdWVzX3N1cHBvcnRlZCI6WyJ1cm46ZWlkYXM6bG9hOmhpZ2giXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJub25lIl19" // swiftlint:disable:this line_length
            .data(using: .ascii)!
        let signature = try! key.sign(message: message)
        XCTAssertTrue(try! key.publicKey.verify(signature: signature, message: message))
    }
}
