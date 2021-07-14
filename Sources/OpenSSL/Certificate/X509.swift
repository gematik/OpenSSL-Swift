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

@_implementationOnly import COpenSSL
import Foundation

/// X509 certificate
public class X509 {
    /// Corresponding signature algorithms of `X.509` certificates.
    public enum SignatureAlgorithm {
        /// ECDSA with SHA 256
        case ecdsaWithSHA256
        /// Not supported by this class
        case unsupported
    }

    let x509: OpaquePointer

    init(owning x509: OpaquePointer) throws {
        guard X509_up_ref(x509) == 1 else {
            throw OpenSSLError(name: "Internal error copying x509 structure")
        }
        self.x509 = x509
    }

    /// Initialize a X509 certificate from DER representation
    ///
    /// - Parameter derRepresentation: raw DER bytes
    /// - Throws:  `OpenSSLError` when the certificate could not be initialized
    public init(der: Data) throws {
        x509 = try der.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            var bytesPtr = buffer.bindMemory(to: UInt8.self).baseAddress

            guard let rawX509 = d2i_X509(nil, &bytesPtr, buffer.count) else {
                throw OpenSSLError(name: "Certificate not DER encoded")
            }

            return rawX509
        }
    }

    /// Initialize a X509 certificate from PEM encoded data (contains *-----BEGIN CERTIFICATE-----*)
    ///
    /// - Parameter pem: `Data` encoding the PEM string
    /// - Throws: `OpenSSLError` when the certificate could not be initialized
    public init(pem: Data) throws {
        x509 = try pem.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            let bytesPtr = buffer.bindMemory(to: UInt8.self).baseAddress
            let certBio = BIO_new_mem_buf(bytesPtr, Int32(buffer.count))
            defer {
                BIO_free(certBio)
            }

            guard let rawX509 = PEM_read_bio_X509(certBio, nil, nil, nil) else {
                throw OpenSSLError(name: "Certificate not PEM encoded")
            }

            return rawX509
        }
    }

    /// De-initialize
    deinit {
        X509_free(x509)
    }

    /// Return the raw bytes of the DER representation
    public var derBytes: Data? {
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let length = i2d_X509(x509, &dataPtr)
        guard length > 0, let safeDataPtr = dataPtr else {
            return nil
        }

        return Data(bytesNoCopy: safeDataPtr, count: Int(length), deallocator: .free)
    }

    /// Return the certificates serial number as decimal `String`
    ///
    /// - Returns: serial number as decimal `String`
    /// - Throws: `OpenSSLError` when reading or converting the serial number
    public func serialNumber() throws -> String {
        guard let serial = X509_get0_serialNumber(x509),
              let bn = ASN1_INTEGER_to_BN(serial, nil) else { // swiftlint:disable:this identifier_name
            throw OpenSSLError(name: "Unable to convert ASN1INTEGER to BN")
        }
        defer {
            BN_free(bn)
        }
        guard let dec: UnsafeMutablePointer<CChar> = BN_bn2dec(bn) else {
            throw OpenSSLError(name: "Unable to convert BN to decimal string")
        }

        defer {
            dec.deallocate()
        }

        return String(cString: dec)
    }

    /// Return the the signature algorithm used when validating signatures with this certificate
    ///
    /// - Returns: `SignatureAlgorithm`
    public func signatureAlgorithm() -> SignatureAlgorithm {
        let nid = Int(X509_get_signature_nid(x509))
        if nid == NID_ecdsa_with_SHA256 {
            return .ecdsaWithSHA256
        } else {
            return .unsupported
        }
    }

    /// Return the certificate's issuer X500 Principal representation as DER encoded `Data`
    /// (ex: "CN=GEM.KOMP-CA10 TEST-ONLY, OU=Komponenten-CA der Telematikinfrastruktur, O=gematik GmbH NOT-VALID, C=DE")
    ///
    /// - Returns: issuer DER encoded data if successful, else nil
    public func issuerX500PrincipalDEREncoded() -> Data? {
        guard let name = X509_get_issuer_name(x509) else {
            return nil
        }
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let length = i2d_X509_NAME(name, &dataPtr)
        guard length > 0, let safeDataPtr = dataPtr else {
            return nil
        }
        return Data(bytesNoCopy: safeDataPtr, count: Int(length), deallocator: .free)
    }

    /// Return the certificate's subject X500 Principal representation as DER encoded `Data`
    /// (ex: "CN=GEM.KOMP-CA10 TEST-ONLY, OU=Komponenten-CA der Telematikinfrastruktur, O=gematik GmbH NOT-VALID, C=DE")
    ///
    /// - Returns: subject DER encoded data if successful, else nil
    public func subjectX500PrincipalDEREncoded() -> Data? {
        guard let name = X509_get_subject_name(x509) else {
            return nil
        }
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let length = i2d_X509_NAME(name, &dataPtr)
        guard length > 0, let safeDataPtr = dataPtr else {
            return nil
        }
        return Data(bytesNoCopy: safeDataPtr, count: Int(length), deallocator: .free)
    }

    /// Convenience function that return the certificate's issuer in one line
    ///
    /// - Returns: formatted issuer `String`
    /// - Throws: `OpenSSLError` when retrieving issuer from X509 certificate
    public func issuerOneLine() throws -> String {
        guard let buf = X509_NAME_oneline(X509_get_issuer_name(x509), nil, 0) else {
            throw OpenSSLError(name: "Error retrieving issuer from X509 certificate")
        }
        defer {
            free(buf)
        }
        return String(cString: buf)
    }

    /// Convenience function that return the certificate's subject in one line
    ///
    /// - Returns: formatted subject `String`
    /// - Throws: `OpenSSLError` when retrieving subject from X509 certificate
    public func subjectOneLine() throws -> String {
        guard let buf = X509_NAME_oneline(X509_get_subject_name(x509), nil, 0) else {
            throw OpenSSLError(name: "Error retrieving subject from X509 certificate")
        }
        defer {
            free(buf)
        }
        return String(cString: buf)
    }

    /// Return the certificate's `notBefore` field
    ///
    /// - Returns: the certificate's `notBefore` field as `Date`
    /// - Throws: `OpenSSLError` when converting certificate date
    public func notBefore() throws -> Date {
        guard let notBefore = X509_get0_notBefore(x509) else {
            throw OpenSSLError(name: "NotBefore not found")
        }

        return try notBefore.asFoundationDate()
    }

    /// Return the certificate's `notAfter` field.
    ///
    /// - Returns: the certificate's `notAfter` field as `Date`
    /// - Throws: `OpenSSLError` when converting certificate date
    public func notAfter() throws -> Date {
        guard let notAfter = X509_get0_notAfter(x509) else {
            throw OpenSSLError(name: "NotAfter not found")
        }

        return try notAfter.asFoundationDate()
    }

    /// Check whether the certificate is a valid CA certificate
    public var isValidCaCertificate: Bool {
        X509_check_ca(x509) > 0
    }

    /// Check whether another certificate is issued by the subject of `self`.
    /// E.g. self is the signing authority (CA) for the given `other` certificate.
    ///
    /// - Parameter other: other `X509` holding the supposed issuer
    /// - Returns: true, if subject of `self` issued the other certificate
    public func issued(_ other: X509) -> Bool {
        X509_check_issued(x509, other.x509) == 0
    }

    /// Compute the SHA256 fingerprint of the certificate
    ///
    /// - Returns: the computed SHA256 fingerprint as `Data`
    /// - Throws: `OpenSSLError` when computing fingerprint
    public func sha256Fingerprint() throws -> Data {
        let algo = EVP_sha256()
        var digestLength: CUnsignedInt = 0

        var digestBuffer = [UInt8](repeating: 0x0, count: Int(EVP_MAX_MD_SIZE))
        guard X509_digest(x509, algo, &digestBuffer, &digestLength) == 1
        else {
            throw OpenSSLError(name: "Error computing fingerprint")
        }

        return Data(digestBuffer[0 ..< Int(digestLength)])
    }

    /// Validate the certificate with a trust store
    ///
    /// - Parameter trustStore: Array of `X509` certificates composing the trusted store
    /// - Returns: true, if the certificate could be validated
    /// - Throws: `OpenSSLError` when trust store is empty
    public func validateWith<C: Collection>(trustStore: C) throws -> Bool where C.Element == X509 {
        if trustStore.isEmpty {
            throw OpenSSLError(name: "Trust store must not be empty")
        }

        let store = X509_STORE_new()
        defer {
            X509_STORE_free(store)
        }
        for trustedCert in trustStore {
            guard X509_STORE_add_cert(store, trustedCert.x509) == 1 else {
                throw OpenSSLError(name: "Error populating the X.509 trust store")
            }
        }

        let ctx = X509_STORE_CTX_new()
        defer {
            X509_STORE_CTX_free(ctx)
        }
        guard X509_STORE_CTX_init(ctx, store, x509, nil) == 1 else {
            throw OpenSSLError(name: "Error initialising the X.509 trust store context")
        }

        return X509_verify_cert(ctx) == 1
    }
}

// swiftlint:disable:next no_extension_access_modifier
private extension UnsafePointer where Pointee == ASN1_TIME {
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
            throw OpenSSLError(name: "Error converting certificate date")
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
            throw OpenSSLError(name: "Unable to validate serial number decimal string")
        }

        guard let date = Self.dateFormatterWithTimezone.date(from: string) else {
            throw OpenSSLError(name: "Error converting certificate date")
        }

        return date
    }
}

extension X509: Equatable {
    public static func ==(lhs: X509, rhs: X509) -> Bool {
        do {
            return try lhs.sha256Fingerprint() == rhs.sha256Fingerprint()
        } catch {
            return false
        }
    }
}

extension X509 {
    /// Convenience function for parsing the certificate's BrainpoolP256r1 PublicKey for verification, if it exists
    ///
    /// - Returns: Parsed `BrainpoolP256r1.Verify.PublicKey`, if the certificate actually supports one, else nil
    public func brainpoolP256r1VerifyPublicKey() -> BrainpoolP256r1.Verify.PublicKey? {
        let publicKey = X509_get_pubkey(x509) // EVP_PKEY
        defer {
            EVP_PKEY_free(publicKey)
        }

        guard NID_X9_62_id_ecPublicKey == EVP_PKEY_id(publicKey),
              let ecKey = EVP_PKEY_get0_EC_KEY(publicKey),
              NID_brainpoolP256r1 == EC_GROUP_get_curve_name(EC_KEY_get0_group(ecKey)),
              let duplicate = EC_KEY_dup(ecKey) else {
            return nil
        }

        return BrainpoolP256r1.Verify.PublicKey(impl: ECPublicKeyImpl<BrainpoolP256r1.Curve>(pubKey: duplicate))
    }

    /// Convenience function for parsing the certificate's BrainpoolP256r1 PublicKey for key exchange, if it exists
    ///
    /// - Returns: Parsed `BrainpoolP256r1.KeyExchange.PublicKey`, if the certificate actually supports one, else nil
    public func brainpoolP256r1KeyExchangePublicKey() -> BrainpoolP256r1.KeyExchange.PublicKey? {
        let publicKey = X509_get_pubkey(x509) // EVP_PKEY
        defer {
            EVP_PKEY_free(publicKey)
        }

        guard NID_X9_62_id_ecPublicKey == EVP_PKEY_id(publicKey),
              let ecKey = EVP_PKEY_get0_EC_KEY(publicKey),
              NID_brainpoolP256r1 == EC_GROUP_get_curve_name(EC_KEY_get0_group(ecKey)),
              let duplicate = EC_KEY_dup(ecKey) else {
            return nil
        }

        return BrainpoolP256r1.KeyExchange.PublicKey(impl: ECPublicKeyImpl<BrainpoolP256r1.Curve>(pubKey: duplicate))
    }
}
