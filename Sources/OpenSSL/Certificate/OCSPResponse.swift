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

@_implementationOnly import COpenSSL
import Foundation

/// OCSP Response
public class OCSPResponse {
    let ocsp: OpaquePointer

    /// Initialize a OCSP Response from DER representation
    ///
    /// - Parameter derRepresentation: raw DER bytes
    /// - Throws:  `OpenSSLError` when the response could not be initialized
    public init(der: Data) throws {
        ocsp = try der.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            var bytesPtr = buffer.bindMemory(to: UInt8.self).baseAddress

            guard let raw = d2i_OCSP_RESPONSE(nil, &bytesPtr, buffer.count) else {
                throw OpenSSLError(name: "OCSPResponse not DER encoded")
            }

            return raw
        }
    }

    /// De-initialize
    deinit {
        OCSP_RESPONSE_free(ocsp)
    }

    public enum Status: Int {
        case successful = 0
        case malformedRequest = 1
        case internalError = 2
        case tryLater = 3
        case sigRequired = 4
        case unauthorized = 5
    }

    /// Returns the response status value
    ///
    /// - Returns: `OCSP.Status` value
    public func status() -> Status {
        let res = Int(OCSP_response_status(ocsp))
        guard let status = Status(rawValue: res) else {
            return .internalError
        }
        return status
    }

    /// Extract the *producedAt* field from the basis response.
    ///
    /// - Returns: `Date` from the *producedAt* field
    /// - Throws: OpenSSL error on internal error
    public func producedAt() throws -> Date {
        let basic = OCSP_response_get1_basic(ocsp)
        defer {
            OCSP_BASICRESP_free(basic)
        }

        guard let producedAt = OCSP_resp_get0_produced_at(basic) else {
            throw OpenSSLError(name: "ProducedAt not found")
        }
        return try producedAt.asFoundationDate()
    }

    public enum CertStatus: Int {
        case good = 0
        case revoked = 1
        case unknown = 2
        case requestedCertificateNotInResponse = 99
    }

    /// Search the OCSP response for a status information for a given `X509` certificate.
    /// Note: the issuer of the certificate has also to be provided
    ///
    /// - Parameters:
    ///   - for: the certificate the status is requested for
    ///   - issuer: the issuer of the status requested certificate
    /// - Returns: `OCSPResponse.CertStatus` value
    /// - Throws: `OpenSSLError` on internal error
    public func certificateStatus(for: X509, issuer: X509) throws -> CertStatus {
        let certId: OpaquePointer = OCSP_cert_to_id(EVP_sha1(), `for`.x509, issuer.x509)
        defer {
            OCSP_CERTID_free(certId)
        }
        let basic = OCSP_response_get1_basic(ocsp)
        defer {
            OCSP_BASICRESP_free(basic)
        }

        var status: CInt = -1
        let res = OCSP_resp_find_status(basic, certId, &status, nil, nil, nil, nil)
        guard res == 1 else {
            return .requestedCertificateNotInResponse
        }

        guard let certStatus = CertStatus(rawValue: Int(status)) else {
            throw OpenSSLError(name: "Internal error extracting certificate status")
        }

        return certStatus
    }

    /// Attempts to retrieve the certificate that directly signed this response.
    ///
    /// - Returns: The signing certificate if it was included in the certs field of the response.
    /// - Throws: OpenSSL error when internal error error certificate parsing error.
    public func getSigner() throws -> X509? {
        let basic = OCSP_response_get1_basic(ocsp)
        defer {
            OCSP_BASICRESP_free(basic)
        }

        var x509Pointer: OpaquePointer? = X509_new()
        let res = OCSP_resp_get0_signer(basic, &x509Pointer, nil)

        guard res == 1 else {
            return nil
        }

        // Note: res == 1 should guarantee a valid x509Pointer
        guard let x509 = x509Pointer else {
            throw OpenSSLError(name: "Internal error getting the OCSP response signer")
        }
        return try X509(owning: x509)
    }

    /// Checks that the basic response message is correctly signed and that the signer certificate can be validated.
    /// For further info see https://www.openssl.org/docs/man1.1.0/man3/OCSP_resp_get0.html -> OCSP_basic_verify()
    ///
    /// - Parameters:
    ///   - trustedStore: a collection of trusted certificates
    ///   - options: flags for taking influence on the behavior of the function
    /// - Returns: true if the OCSP response is correctly signed and the signer certificate can be validated
    /// - Throws: OpenSSLError on a fatal internal error
    public func basicVerifyWith<C: Collection>(trustedStore: C, options: BasicVerifyOptions = []) throws -> Bool
        where C.Element == X509 {
        let basic = OCSP_response_get1_basic(ocsp)
        defer {
            OCSP_BASICRESP_free(basic)
        }
        let x509TrustedStore = X509_STORE_new()
        defer {
            X509_STORE_free(x509TrustedStore)
        }
        for trustedCert in trustedStore {
            guard X509_STORE_add_cert(x509TrustedStore, trustedCert.x509) == 1 else {
                throw OpenSSLError(name: "Error populating the X.509 trust store")
            }
        }

        let flags = options.rawValue
        let res = OCSP_basic_verify(basic, nil, x509TrustedStore, flags)
        if res == 1 {
            return true
        } else if res == 0 {
            return false
        } else {
            throw OpenSSLError(name: "Fatal error when trying to verify OCSP response")
        }
    }

    /// Flags for function `basicVerify()`.
    /// For usage info refer to https://www.openssl.org/docs/man1.1.0/man3/OCSP_resp_get0.html -> OCSP_basic_verify()
    public struct BasicVerifyOptions: OptionSet {
        public let rawValue: UInt

        public init(rawValue: UInt) {
            self.rawValue = rawValue
        }

        public static let noIntern = BasicVerifyOptions(rawValue: UInt(OCSP_NOINTERN))
        public static let noSigs = BasicVerifyOptions(rawValue: UInt(OCSP_NOSIGS))
        public static let noVerify = BasicVerifyOptions(rawValue: UInt(OCSP_NOVERIFY))
        public static let trustOther = BasicVerifyOptions(rawValue: UInt(OCSP_TRUSTOTHER))
        public static let noChain = BasicVerifyOptions(rawValue: UInt(OCSP_NOCHAIN))
        public static let noChecks = BasicVerifyOptions(rawValue: UInt(OCSP_NOCHECKS))
        public static let noExplicit = BasicVerifyOptions(rawValue: UInt(OCSP_NOEXPLICIT))
    }
}

// swiftlint:disable:next no_extension_access_modifier
private extension UnsafePointer where Pointee == ASN1_GENERALIZEDTIME {
    // When handling ASN1_TIME, we always assume the format MMM DD HH:MM:SS YYYY [GMT]
    private static let dateFormatterWithTimezone: DateFormatter = {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "MMM dd HH:mm:ss yyyy ZZZ"
        dateFormatter.locale = Locale(identifier: "en_US")

        return dateFormatter
    }()

    func asFoundationDate() throws -> Date {
        let bio = BIO_new(BIO_s_mem())
        defer {
            BIO_free(bio)
        }

        guard ASN1_TIME_print(bio, self) == 1 else {
            throw OpenSSLError(name: "Error converting OCSP response date")
        }

        let bufferSize: CInt = 128
        var buffer = [UInt8](repeating: 0x0, count: Int(bufferSize))
        var data = Data()
        var readBytes: CInt = 0

        repeat {
            readBytes = BIO_read(bio, &buffer, bufferSize)
            if readBytes > 0 {
                data.append(contentsOf: buffer[0 ..< Int(readBytes)])
            }
        } while readBytes > 0

        guard let string = String(data: data, encoding: .utf8) else {
            throw OpenSSLError(name: "Unable to validate ASN1 TIME string")
        }

        guard let date = Self.dateFormatterWithTimezone.date(from: string) else {
            throw OpenSSLError(name: "Error converting date from string")
        }

        return date
    }
}
