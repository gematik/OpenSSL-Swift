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

import DataKit
import Foundation
@testable import OpenSSL
import XCTest

// swiftlint:disable line_length force_try
final class CMSContentInfoTests: XCTestCase {
    func testEncryptRSAOnly() throws {
        // given
        let x509rsa1 = try X509(pem: x509rsa1.data(using: .utf8)!)
        let x509rsa2 = try X509(der: Base64.decode(string: x509rsa2))
        let recipients = [x509rsa1, x509rsa2]
        let data = message.data(using: .utf8)!

        // when
        let cms = try CMSContentInfo.encryptPartial(data: data)
        try cms.addRecipientsRSAOnly(recipients)
        try cms.final(data: data)

        // then expect sut to contain a byte sequence that represents
        // SEQUENCE (2 elem)
        //            OBJECT IDENTIFIER 1.2.840.113549.1.1.7 rsaOAEP (PKCS #1)
        //            SEQUENCE (2 elem)
        //              [0] (1 elem)
        //                SEQUENCE (1 elem)
        //                  OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
        //              [1] (1 elem)
        //                SEQUENCE (2 elem)
        //                  OBJECT IDENTIFIER 1.2.840.113549.1.1.8 pkcs1-MGF (PKCS #1)
        //                  SEQUENCE (1 elem)
        //                    OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
        XCTAssertTrue(cms.derBytes?.hexString()
            .contains(
                "303806092A864886F70D010107302BA00D300B0609608648016503040201A11A301806092A864886F70D010108300B0609608648016503040201"
            ) ??
            false)
    }

    let message =
        """
        {
        \t"version": "2",
        \t"supplyOptionsType": "delivery",
        \t"name": "Dr. Maximilian von Muster",
        \t"address": [
        \t\t"Bundesallee",
        \t\t"312",
        \t\t"12345",
        \t\t"Berlin"
        \t],
        \t"hint": "Bitte im Morsecode klingeln: -.-.",
        \t"text": "123456",
        \t"phone": "004916094858168",
        \t"mail": "max@musterfrau.de",
        \t"transaction": "ee63e415-9a99-4051-ab07-257632faf985",
        \t"taskID": "160.123.456.789.123.58",
        \t"accessCode": "777bea0e13cc9c42ceec14aec3ddee2263325dc2c6c699db115f58fe423607ea"
        }
        """

    let x509rsa1 =
        """
        -----BEGIN CERTIFICATE-----
        MIIFSTCCBDGgAwIBAgIHAXLewUJXxjANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UE
        BhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxSDBGBgNVBAsM
        P0luc3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIgVGVsZW1h
        dGlraW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLlNNQ0ItQ0EyNCBURVNULU9O
        TFkwHhcNMjAwMTI0MDAwMDAwWhcNMjQxMjExMjM1OTU5WjCB5TELMAkGA1UEBhMC
        REUxEDAOBgNVBAcMB0hhbWJ1cmcxDjAMBgNVBBEMBTIyNDUzMRgwFgYDVQQJDA9I
        ZXNlbHN0w7xja2VuIDkxKjAoBgNVBAoMITMtU01DLUItVGVzdGthcnRlLTg4MzEx
        MDAwMDExNjg3MzEdMBsGA1UEBRMUODAyNzY4ODMxMTAwMDAxMTY4NzMxEjAQBgNV
        BAQMCVNjaHJhw59lcjESMBAGA1UEKgwJU2llZ2ZyaWVkMScwJQYDVQQDDB5BcG90
        aGVrZSBhbSBGbHVnaGFmZW5URVNULU9OTFkwggEiMA0GCSqGSIb3DQEBAQUAA4IB
        DwAwggEKAoIBAQCZ9ihWMq2T1C9OEoXpbWJWjALF/X6pbRmzmln2gdRxW7k/BS59
        YpONamWX3Wmjc7ELpmiU+5atOpSrFhS7QCQomTyCbnuIYOB6WVaYgDREceZ7bu29
        QxD04aHGGrOwaU/55i4f3JTa88QtyMOqPEA/YW3XoCKdPwouiVEP8AXJ+8dRiYCS
        SzPUKOOy+R53sMhrTmpkwGNfOmq9Kg1uX8NRDg0Lamv41O9XbsfJTuzVa4EcKALx
        HEMprsUokV9WaGVK0nHCyU0TTi6V9EqslVoK1iyMgUUl2nfx1/aRtUViFbXtd6DR
        6SeUhcqIzFOVBnl9EY4alAnHfR/qE8iBe6bbAgMBAAGjggFFMIIBQTAdBgNVHQ4E
        FgQUGRLcBNLvAKTcCYYIS+HLzaac0EAwDAYDVR0TAQH/BAIwADA4BggrBgEFBQcB
        AQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9laGNhLmdlbWF0aWsuZGUvb2NzcC8w
        DgYDVR0PAQH/BAQDAgQwMB8GA1UdIwQYMBaAFHrp4W/qFFkWBe4D6dP9Iave6dme
        MCAGA1UdIAQZMBcwCgYIKoIUAEwEgSMwCQYHKoIUAEwETDCBhAYFKyQIAwMEezB5
        pCgwJjELMAkGA1UEBhMCREUxFzAVBgNVBAoMDmdlbWF0aWsgQmVybGluME0wSzBJ
        MEcwFwwVw5ZmZmVudGxpY2hlIEFwb3RoZWtlMAkGByqCFABMBDYTITMtU01DLUIt
        VGVzdGthcnRlLTg4MzExMDAwMDExNjg3MzANBgkqhkiG9w0BAQsFAAOCAQEALmkJ
        S6sCvx0cyDcFMRFiCJ7Po3H6jAPGgVmuQsldo+AHcjN7YAuM/7JwOBulvycZOEBi
        Mf+NYkjfzQRM16h9SHspjFsr8yD78u0JfdKJEYWnpTUEDTl0C0ssv++obWLyw/lj
        1623pjn5Kb0x5yjEbzSGo3kk5S050Bnwf39JGVzv2M1j31y9CQQSAxT3EKl937Gj
        306acGmt6vjDDd0GB8P6nPreulTYh1M0Tlli53gfP7o987q2Pq/jIK13ExF6t5WN
        PCqpN2JbFY8waA6PzoT57zKdT6sB/w26rA2Gnc9eGp9pZ9DH11Qw+x+SArCs1eEh
        0jqYhPIqIs2gJPl3hw==
        -----END CERTIFICATE-----
        """

    let x509rsa2 =
        "MIIE4TCCA8mgAwIBAgIDD0vlMA0GCSqGSIb3DQEBCwUAMIGuMQswCQYDVQQGEwJERTEzMDEGA1UECgwqQXRvcyBJbmZvcm1hdGlvbiBUZWNobm9sb2d5IEdtYkggTk9ULVZBTElEMUgwRgYDVQQLDD9JbnN0aXR1dGlvbiBkZXMgR2VzdW5kaGVpdHN3ZXNlbnMtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxIDAeBgNVBAMMF0FUT1MuU01DQi1DQTMgVEVTVC1PTkxZMB4XDTE5MDkxNzEyMzYxNloXDTI0MDkxNzEyMzYxNlowXDELMAkGA1UEBhMCREUxIDAeBgNVBAoMFzEtMjExMjM0NTY3ODkgTk9ULVZBTElEMSswKQYDVQQDDCJBcnp0cHJheGlzIERyLiBBxJ9hb8SfbHUgVEVTVC1PTkxZMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmdmUeBLB6UDh4u8FAvi7B3hpAhJYXBlx+IJXLiSrhgCu/T/L5vVlCQb+1gYybWhHT5YlxafTJpOcXSfcixJbFWGxn+iQLqo+LCp/ljLBz5JoU+IXIxRKZCi5SZ9APeglGs4R0/xpPBtsJzihFXVu+B8qGm2oqmvVV91u+MoJ5asC6C+rVOecLxqy/OdmeKfaNSgH2NxVzNc19VmFUkFDGUFJjG4ZgatW4V6AuAhiPnDkEg8gfXr5L7ycQRZUNlEGMmDhh+noHU/doxSU2cgBaiTZNmu17FJLXlBLRISpWcQitcjOkjrJDt4Z0Yta64yZe13+a5dANh32Zeeg5jDQRQIDAQABo4IBVzCCAVMwHQYDVR0OBBYEFF/uDhGziRKzsUC9Nkat5xQojOUZMA4GA1UdDwEB/wQEAwIEMDAMBgNVHRMBAf8EAjAAMCAGA1UdIAQZMBcwCQYHKoIUAEwETDAKBggqghQATASBIzBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLXNtY2IuZWdrLXRlc3QtdHNwLmRlL0FUT1MuU01DQi1DQTNfVEVTVC1PTkxZLmNybDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQUHMAGGIGh0dHA6Ly9vY3NwLXNtY2IuZWdrLXRlc3QtdHNwLmRlMB8GA1UdIwQYMBaAFD+eHl4mKtYMlaF4nqrz1drzQaf8MEUGBSskCAMDBDwwOjA4MDYwNDAyMBYMFEJldHJpZWJzc3TDpHR0ZSBBcnp0MAkGByqCFABMBDITDTEtMjExMjM0NTY3ODkwDQYJKoZIhvcNAQELBQADggEBACUnL3MxjyoEyUBRxcBAjl7FdePW0O1/UCeDAbH2b4ob9GjMGjL5OoBmhj9GsUORg/K4cIiqTot2TcPtdooKCI5a5Jupp0nYoAuzdrNlvGYEm0S/cvlyYJXjfhrEIHmlDY0/hpJX3S/hYgkniJ1Wg70MfLLcib05+31OijZmEzpChioIm4KmumEKU4ODsLWr/4OEw9KCYfuNpjiSyyAEd2pMgnGU8MKCJhrR/ZKSteAxAPKTXVtNTKndbptvcsaEZPp//vNdbBh+k8P642P2DHYfeDoUgivEYXdE5ABixtG9sk1Q2DPfTXoS+CKv45ae0vejBnRjuA28lmkmuIp+f+s="

    let x509eccPem =
        """
        -----BEGIN CERTIFICATE-----
        MIIDvDCCA2OgAwIBAgIHAN6t0nKF8TAKBggqhkjOPQQDAjCBmTELMAkGA1UEBhMC
        REUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxSDBGBgNVBAsMP0lu
        c3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIgVGVsZW1hdGlr
        aW5mcmFzdHJ1a3R1cjEfMB0GA1UEAwwWR0VNLlNNQ0ItQ0E5IFRFU1QtT05MWTAe
        Fw0yMDAxMjQwMDAwMDBaFw0yNDEyMTEyMzU5NTlaMIHlMQswCQYDVQQGEwJERTEQ
        MA4GA1UEBwwHSGFtYnVyZzEOMAwGA1UEEQwFMjI0NTMxGDAWBgNVBAkMD0hlc2Vs
        c3TDvGNrZW4gOTEqMCgGA1UECgwhMy1TTUMtQi1UZXN0a2FydGUtODgzMTEwMDAw
        MTE2ODczMR0wGwYDVQQFExQ4MDI3Njg4MzExMDAwMDExNjg3MzESMBAGA1UEBAwJ
        U2NocmHDn2VyMRIwEAYDVQQqDAlTaWVnZnJpZWQxJzAlBgNVBAMMHkFwb3RoZWtl
        IGFtIEZsdWdoYWZlblRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNC
        AASQgPBIpSefm85uPe99rvPzdr/FjR8BjDf+o2Z6vaRpO2ACx7ehSNuDHW+OtOZ5
        hvm7ONskNAOoWasDt1wJ4t1eo4IBRTCCAUEwHQYDVR0OBBYEFDbdoSwPnHLJr04A
        LfE7RkGmYy46MA4GA1UdDwEB/wQEAwIDCDAgBgNVHSAEGTAXMAoGCCqCFABMBIEj
        MAkGByqCFABMBEwwHwYDVR0jBBgwFoAUYoiaxN78o/OTOcufkOcTmj2JzHUwOAYI
        KwYBBQUHAQEELDAqMCgGCCsGAQUFBzABhhxodHRwOi8vZWhjYS5nZW1hdGlrLmRl
        L29jc3AvMAwGA1UdEwEB/wQCMAAwgYQGBSskCAMDBHsweaQoMCYxCzAJBgNVBAYT
        AkRFMRcwFQYDVQQKDA5nZW1hdGlrIEJlcmxpbjBNMEswSTBHMBcMFcOWZmZlbnRs
        aWNoZSBBcG90aGVrZTAJBgcqghQATAQ2EyEzLVNNQy1CLVRlc3RrYXJ0ZS04ODMx
        MTAwMDAxMTY4NzMwCgYIKoZIzj0EAwIDRwAwRAIgOOxowEl8laLh5qRTy5prce49
        kxKocntxvCCcjtSHwlYCIG3AuFFTWw/LVvopPTrjv6neLca0kKFfIs3Nw1bPw/VG
        -----END CERTIFICATE-----
        """
}
