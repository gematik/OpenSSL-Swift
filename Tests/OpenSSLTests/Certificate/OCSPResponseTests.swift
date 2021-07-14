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
import Foundation
@testable import OpenSSL
import XCTest

final class OCSPResponseTests: XCTestCase {
    let bundle = Bundle(for: OCSPResponseTests.self)
    // swiftlint:disable force_try
    lazy var vauOcspResponse: OCSPResponse = {
        let fileName = "OCSP/vau-oscp-response.der.base64"
        let base64 = try! ResourceFileReader.readFileInResourceBundle(filePath: fileName, for: bundle)
        return try! OCSPResponse(der: Base64.decode(data: base64))
    }()

    lazy var vauOcspResponseNoKnownSignerCa: OCSPResponse = {
        let fileName = "OCSP/vau-ocsp-response-no-signing-ca.der.base64"
        let base64 = try! ResourceFileReader.readFileInResourceBundle(filePath: fileName, for: bundle)
        return try! OCSPResponse(der: Base64.decode(data: base64))
    }()

    func testOCSPResponseStatus() {
        XCTAssertEqual(vauOcspResponseNoKnownSignerCa.status(), .successful)
    }

    func testProducedAt() throws {
        // when
        let producedAt = try vauOcspResponseNoKnownSignerCa.producedAt()

        // then
        let expectedProducedAt = ISO8601DateFormatter().date(from: "2021-03-25T12:54:31Z")
        XCTAssertEqual(producedAt, expectedProducedAt)
    }

    func testCertificateStatus() throws {
        // given
        let issuer: X509 = {
            let filename = "X509/GEM.KOMP-CA10-TEST-ONLY.pem"
            return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
        }()
        let eeCert: X509 = {
            let filename = "X509/c.fd.enc-erp-erpserverReferenz.pem"
            return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
        }()

        // when
        let certificateStatus = try vauOcspResponseNoKnownSignerCa.certificateStatus(for: eeCert, issuer: issuer)

        // then
        XCTAssertEqual(certificateStatus, .good)
    }

    func testGetSignerCertificate() throws {
        // when
        let signerCertificate = try vauOcspResponseNoKnownSignerCa.getSigner()

        // expect
        XCTAssertEqual(try signerCertificate?.serialNumber(), "119197")
    }

    func testOcspBasicVerify_pathValidation() throws {
        // given
        let ocspSignerCa: X509 = {
            let filename = "X509/GEM.OCSP-CA9-TEST-ONLY.pem"
            return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
        }()
        let rootCa: X509 = {
            let filename = "X509/GEM.RCA3-TEST-ONLY.pem"
            return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
        }()
        let trustedStore = [ocspSignerCa, rootCa]

        // then
        // Signer certificate does not meet the OCSP issuer criteria including potential delegation
        XCTAssertFalse(try vauOcspResponse.basicVerifyWith(trustedStore: trustedStore))

        // After successful path validation the function returns success if the OCSP_NOCHECKS flag is set.
        // Note: Path validation could possibly fail in the future when certificates expire.
        var options: OCSPResponse.BasicVerifyOptions = [.noChecks]
        try vauOcspResponse.basicVerifyWith(trustedStore: [ocspSignerCa, rootCa], options: options)
    }
}
