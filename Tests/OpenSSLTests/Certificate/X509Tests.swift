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

import Foundation
@testable import OpenSSL
import XCTest

// swiftlint:disable line_length force_try
final class X509Tests: XCTestCase {
    let bundle = Bundle(for: X509Tests.self)
    lazy var sut: X509 = {
        let filename = "X509/GEM.DISCOVERY-DOC-TEST-ONLY.pem"
        return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
    }()

    lazy var caCertificate: X509 = {
        let filename = "X509/GEM.KOMP-CA10-TEST-ONLY.pem"
        return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
    }()

    lazy var rootCertificate: X509 = {
        let filename = "X509/GEM.RCA3-TEST-ONLY.pem"
        return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
    }()

    func testDerBytes() throws {
        // when
        let derBytes = sut.derBytes

        // then
        let base64 =
            "MIICsTCCAligAwIBAgIHA61I5ACUjTAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxMjAwBgNVBAsMKUtvbXBvbmVudGVuLUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMSAwHgYDVQQDDBdHRU0uS09NUC1DQTEwIFRFU1QtT05MWTAeFw0yMDA4MDQwMDAwMDBaFw0yNTA4MDQyMzU5NTlaMEkxCzAJBgNVBAYTAkRFMSYwJAYDVQQKDB1nZW1hdGlrIFRFU1QtT05MWSAtIE5PVC1WQUxJRDESMBAGA1UEAwwJSURQIFNpZyAxMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABJZQrG1NWxIB3kz/6Z2zojlkJqN3vJXZ3EZnJ6JXTXw5ZDFZ5XjwWmtgfomv3VOV7qzI5ycUSJysMWDEu3mqRcajge0wgeowHQYDVR0OBBYEFJ8DVLAZWT+BlojTD4MT/Na+ES8YMDgGCCsGAQUFBwEBBCwwKjAoBggrBgEFBQcwAYYcaHR0cDovL2VoY2EuZ2VtYXRpay5kZS9vY3NwLzAMBgNVHRMBAf8EAjAAMCEGA1UdIAQaMBgwCgYIKoIUAEwEgUswCgYIKoIUAEwEgSMwHwYDVR0jBBgwFoAUKPD45qnId8xDRduartc6g6wOD6gwLQYFKyQIAwMEJDAiMCAwHjAcMBowDAwKSURQLURpZW5zdDAKBggqghQATASCBDAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDRwAwRAIgVBPhAwyX8HAVH0O0b3+VazpBAWkQNjkEVRkv+EYX1e8CIFdn4O+nivM+XVi9xiKK4dW1R7MD334OpOPTFjeEhIVV"
        let expected = Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
        XCTAssertEqual(derBytes, expected)
    }

    func testX509CertificateSerialNumber() throws {
        // when
        let serialNumber = try sut.serialNumber()

        // then
        XCTAssertEqual(serialNumber, "1034953504625805")
    }

    func testX509CertificateSignatureAlgorithm() {
        // when
        let signatureAlgorithm = sut.signatureAlgorithm()

        // then
        XCTAssertEqual(signatureAlgorithm, .ecdsaWithSHA256)
    }

    func testIssuer() throws {
        // when
        let issuerData = sut.issuerX500PrincipalDEREncoded()

        // then
        XCTAssertEqual(
            issuerData?.hexString(),
            "308184310B3009060355040613024445311F301D060355040A0C1667656D6174696B20476D6248204E4F542D56414C494431323030060355040B0C294B6F6D706F6E656E74656E2D4341206465722054656C656D6174696B696E667261737472756B7475723120301E06035504030C1747454D2E4B4F4D502D4341313020544553542D4F4E4C59"
        )
        XCTAssertTrue(String(data: issuerData!, encoding: .ascii)!.contains("GEM.KOMP-CA10 TEST-ONLY"))
    }

    func testSubject() {
        // when
        let subjectData = sut.subjectX500PrincipalDEREncoded()

        // then
        XCTAssertEqual(
            subjectData?.hexString(),
            "3049310B300906035504061302444531263024060355040A0C1D67656D6174696B20544553542D4F4E4C59202D204E4F542D56414C49443112301006035504030C09494450205369672031"
        )
        XCTAssertTrue(String(data: subjectData!, encoding: .ascii)!.contains("IDP Sig 1"))
    }

    func testX509CertificateNotBeforeAfter() throws {
        // when
        let notBefore = try sut.notBefore()
        let notAfter = try sut.notAfter()

        // then
        let formatter = ISO8601DateFormatter()
        let expectedNotBefore = formatter.date(from: "2020-08-04T00:00:00Z")
        let expectedNotAfter = formatter.date(from: "2025-08-04T23:59:59Z")
        XCTAssertEqual(notBefore, expectedNotBefore)
        XCTAssertEqual(notAfter, expectedNotAfter)
    }

    func testX509CertificateBrainpoolP256r1VerifyPublicKey() throws {
        // when
        let brainpoolP256r1PublicKey = sut.brainpoolP256r1VerifyPublicKey()

        // then
        let expected = try BrainpoolP256r1.Verify.PublicKey(
            x962: Data(
                hex: "049650AC6D4D5B1201DE4CFFE99DB3A2396426A377BC95D9DC466727A2574D7C39643159E578F05A6B607E89AFDD5395EEACC8E72714489CAC3160C4BB79AA45C6"
            )
        )
        XCTAssertNotNil(brainpoolP256r1PublicKey)
        XCTAssertEqual(brainpoolP256r1PublicKey?.rawValue, expected.rawValue)
    }

    func testX509CertificateBrainpoolP256r1KeyExchangePublicKey() throws {
        // when
        let brainpoolP256r1PublicKey = sut.brainpoolP256r1KeyExchangePublicKey()

        // then
        let expected = try BrainpoolP256r1.KeyExchange
            .PublicKey(
                x962: Data(
                    hex: "049650AC6D4D5B1201DE4CFFE99DB3A2396426A377BC95D9DC466727A2574D7C39643159E578F05A6B607E89AFDD5395EEACC8E72714489CAC3160C4BB79AA45C6"
                )
            )
        XCTAssertNotNil(brainpoolP256r1PublicKey)
        XCTAssertEqual(brainpoolP256r1PublicKey?.rawValue, expected.rawValue)
    }

    func testIsValidCaCertificate() {
        XCTAssertTrue(rootCertificate.isValidCaCertificate)
        XCTAssertTrue(caCertificate.isValidCaCertificate)
        XCTAssertFalse(sut.isValidCaCertificate)
    }

    func testIsIssuedBy() throws {
        XCTAssertTrue(caCertificate.issued(sut))
        XCTAssertTrue(rootCertificate.issued(caCertificate))
        XCTAssertFalse(rootCertificate.issued(sut))
    }

    func testValidate() throws {
        XCTAssertTrue(try sut.validateWith(trustStore: [caCertificate, rootCertificate]))
        XCTAssertTrue(try caCertificate.validateWith(trustStore: [rootCertificate]))
        XCTAssertTrue(try rootCertificate.validateWith(trustStore: [rootCertificate]))

        XCTAssertFalse(try sut.validateWith(trustStore: [rootCertificate]))
        XCTAssertFalse(try sut.validateWith(trustStore: [caCertificate]))
    }

    func testX509CertificateComputeSha256Fingerprint() throws {
        // when
        let sha256Fingerprint = try sut.sha256Fingerprint()

        // then
        let expected = try Data(hex: "AB9590D2B1764E21277927A1E084EB2E041E022E62F21C4E59155EB747249CFA")
        XCTAssertEqual(sha256Fingerprint, expected)
    }
}
