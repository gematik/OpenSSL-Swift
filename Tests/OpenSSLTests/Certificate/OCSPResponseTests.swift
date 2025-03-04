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

import Foundation
@testable import OpenSSL
import XCTest

// swiftlint:disable force_try
final class OCSPResponseTests: XCTestCase {
    let bundle = Bundle(for: OCSPResponseTests.self)
    lazy var vauOcspResponse: OCSPResponse = {
        let fileName = "OCSP/vau-oscp-response.der.base64"
        let base64 = try! ResourceFileReader.readFileInResourceBundle(filePath: fileName, for: bundle)
        return try! OCSPResponse(der: Data(base64Encoded: base64)!)
    }()

    lazy var vauOcspResponseNoKnownSignerCa: OCSPResponse = {
        let fileName = "OCSP/vau-ocsp-response-no-signing-ca.der.base64"
        let base64 = try! ResourceFileReader.readFileInResourceBundle(filePath: fileName, for: bundle)
        return try! OCSPResponse(der: Data(base64Encoded: base64)!)
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
            let fileName = "X509/GEM.KOMP-CA28 TEST-ONLY.der.base64"
            let base64 = try! ResourceFileReader.readFileInResourceBundle(filePath: fileName, for: bundle)
            return try! X509(der: Data(base64Encoded: base64)!)
        }()
        let rootCa: X509 = {
            let filename = "X509/GEM.RCA3-TEST-ONLY.pem"
            return try! X509(pem: ResourceFileReader.readFileInResourceBundle(filePath: filename, for: bundle))
        }()
        let trustedStore = [ocspSignerCa, rootCa]

        // then
        /*
          Note: With the updated test data the basicVerifyWith check passes now without setting the flag options.
          The code remains in here for reference.

         // Signer certificate does not meet the OCSP issuer criteria including potential delegation
         XCTAssertFalse(try vauOcspResponse.basicVerifyWith(trustedStore: trustedStore))

         // After successful path validation the function returns success if the OCSP_NOCHECKS flag is set.
         // Note: Path validation could possibly fail in the future when certificates expire.
         let options: OCSPResponse.BasicVerifyOptions = [.noChecks]
         XCTAssertTrue(try vauOcspResponse.basicVerifyWith(trustedStore: trustedStore, options: options))
         */

        XCTAssertTrue(try vauOcspResponse.basicVerifyWith(trustedStore: trustedStore))
    }
}

// swiftlint:enable force_try
