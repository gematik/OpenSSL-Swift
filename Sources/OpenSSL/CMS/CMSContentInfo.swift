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

/// CMSContentInfo
public class CMSContentInfo {
    let cms: OpaquePointer

    init() {
        cms = CMS_ContentInfo_new()
    }

    required init(owningNoCopy cms: OpaquePointer) {
        self.cms = cms
    }

    /// De-initialize
    deinit {
        CMS_ContentInfo_free(cms)
    }

    /// Get the DER byte representation as `Data`
    public var derBytes: Data? {
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let length = i2d_CMS_ContentInfo(cms, &dataPtr)
        guard length > 0, let safeDataPtr = dataPtr else {
            return nil
        }

        return Data(bytesNoCopy: safeDataPtr, count: Int(length), deallocator: .free)
    }

    /// Entry step for the `encryptPartial`, `addRecipients`, `final` (as in `init`, `update`, `final`) cycle.
    ///
    /// - Important: Encryption is done by `aes_256_gcm`
    /// - Parameter data: Data (e.g. a message) to be encrypted
    /// - Returns: A (partially) initialized `CMSContentInfo`
    /// - Throws: `OpenSSLError`
    public static func encryptPartial(data: Data) throws -> Self {
        let flagPartial = UInt32(CMS_PARTIAL) // don't call `finalize` immediately
        let flags = flagPartial

        let cms: OpaquePointer!
        cms = try data.withUnsafeBytes { unsafeRawBufferPointer in
            let bytesPtr = unsafeRawBufferPointer.bindMemory(to: UInt8.self).baseAddress
            let dataBio = BIO_new_mem_buf(bytesPtr, Int32(unsafeRawBufferPointer.count))
            defer { BIO_free(dataBio) }

            guard let ret = CMS_encrypt(nil, dataBio, EVP_aes_256_gcm(), flags) else {
                throw OpenSSLError(name: "Error calling CMS_encrypt()")
            }
            return ret
        }
        return .init(owningNoCopy: cms)
    }

    /// Update step for the `encryptPartial`, `addRecipients`, `final` (as in `init`, `update`, `final`) cycle.
    ///
    /// - Important: This will only work with `X509` certificates that contain a RSA public key!
    /// - Parameter recipients:
    /// - Throws: `OpenSSLError`
    public func addRecipientsRSAOnly(_ recipients: [X509]) throws {
        let flagPartial = UInt32(CMS_PARTIAL) // don't call `finalize` immediately
        let flags = flagPartial

        for recipient in recipients {
            var ri: OpaquePointer! // swiftlint:disable:this identifier_name
            var pctx: OpaquePointer!
            ri = CMS_add1_recipient_cert(cms, recipient.x509, flags | UInt32(CMS_KEY_PARAM))
            pctx = CMS_RecipientInfo_get0_pkey_ctx(ri)
            guard EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) == 1 else {
                throw OpenSSLError(name: "Error calling EVP_PKEY_CTX_set_rsa_oaep_md()")
            }
            guard EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) == 1 else {
                throw OpenSSLError(name: "Error calling EVP_PKEY_CTX_set_rsa_mgf1_md()")
            }
            guard EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) == 1 else {
                throw OpenSSLError(name: "Error calling EVP_PKEY_CTX_set_rsa_padding()")
            }
        }
    }

    /// Final step for the `encryptPartial`, `addRecipients`, `final` (as in `init`, `update`, `final`) cycle.
    ///
    /// - Parameter data: Data (e.g. a message) to be encrypted
    /// - Throws: `OpenSSLError`
    public func final(data: Data) throws {
        let flagPartial = UInt32(CMS_PARTIAL) // don't call `finalize` immediately
        let flags = flagPartial

        try data.withUnsafeBytes { unsafeRawBufferPointer in
            let bytesPtr = unsafeRawBufferPointer.bindMemory(to: UInt8.self).baseAddress
            let dataBio = BIO_new_mem_buf(bytesPtr, Int32(unsafeRawBufferPointer.count))
            defer {
                BIO_free(dataBio)
            }
            guard CMS_final(cms, dataBio, nil, flags) == 1 else {
                throw OpenSSLError(name: "Error calling CMS_final()")
            }
        }
    }
}
