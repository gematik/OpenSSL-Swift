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

/// CMAC calculation package
public enum CMAC {}

extension CMAC {
    /// Stateless, one-shot AES 128 CBC CMAC function
    /// see: https://tools.ietf.org/html/rfc4493
    ///
    /// - Parameters:
    ///   - key: raw key `Data` - must be 16 bytes
    ///   - data: raw message `Data`
    /// - Throws: `OpenSSLError`
    /// - Returns: calculated MAC as `Data`
    public static func aes128cbc_bySteps(key: Data, data: Data) throws -> Data {
        let byteCount = 16
        guard key.count == byteCount else {
            throw OpenSSLError(name: "Key length invalid for CMAC calculation")
        }
        var macT = [UInt8](repeating: 0x0, count: byteCount)
        var outLen = 0
        let macTCount = byteCount

        let mac = EVP_MAC_fetch(nil, "cmac", nil)
        defer {
            EVP_MAC_free(mac)
        }
        let ctx: OpaquePointer = EVP_MAC_CTX_new(mac)
        defer {
            EVP_MAC_CTX_free(ctx)
        }
        var cipher = "aes-128-cbc".cString(using: .utf8)! // swiftlint:disable:this force_unwrapping
        let cipherTag = "cipher".cString(using: .utf8)! // swiftlint:disable:this force_unwrapping
        let subalgParam0 = OSSL_PARAM_construct_utf8_string(cipherTag, &cipher, 0)
        let subalgParam1 = OSSL_PARAM_construct_end()
        let subalgParams = [subalgParam0, subalgParam1]

        guard EVP_MAC_CTX_set_params(ctx, subalgParams) == 1 else {
            throw OpenSSLError(name: "Could not add OSSL_PARAM")
        }

        try key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) in
            try data.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) in
                guard let keyPtrBaseAddress = keyPtr.bindMemory(to: UInt8.self).baseAddress,
                      let msgPtrBaseAddress = msgPtr.bindMemory(to: UInt8.self).baseAddress else {
                    throw OpenSSLError(name: "Error deriving CMAC")
                }

                guard EVP_MAC_init(ctx, keyPtrBaseAddress, byteCount, nil) == 1
                else {
                    throw OpenSSLError(name: "Error EVP_MAC life cycle begin")
                }
                guard EVP_MAC_update(ctx, msgPtrBaseAddress, msgPtr.count) == 1
                else {
                    throw OpenSSLError(name: "Error EVP_MAC life cycle update")
                }
                guard EVP_MAC_final(ctx, &macT, &outLen, macTCount) == 1
                else {
                    throw OpenSSLError(name: "Error EVP_MAC life cycle final")
                }
            }
        }
        return Data(macT)
    }

    /// Stateless, one-shot AES 128 CBC CMAC function
    /// see: https://tools.ietf.org/html/rfc4493
    ///
    /// - Parameters:
    ///   - key: raw key `Data` - must be 16 bytes
    ///   - data: raw message `Data`
    /// - Throws: `OpenSSLError`
    /// - Returns: calculated MAC as `Data`
    public static func aes128cbc(key: Data, data: Data) throws -> Data {
        let byteCount = 16
        guard key.count == byteCount else {
            throw OpenSSLError(name: "Key length invalid for CMAC calculation")
        }
        var macT = [UInt8](repeating: 0x0, count: byteCount)
        var outLen = 0
        let macTCount = byteCount

        try key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) in
            try data.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) in
                guard let keyPtrBaseAddress = keyPtr.bindMemory(to: UInt8.self).baseAddress,
                      let msgPtrBaseAddress = msgPtr.bindMemory(to: UInt8.self).baseAddress else {
                    throw OpenSSLError(name: "Error deriving CMAC")
                }
                EVP_Q_mac(
                    nil,
                    "cmac",
                    nil,
                    "aes-128-cbc",
                    nil,
                    keyPtrBaseAddress,
                    byteCount,
                    msgPtrBaseAddress,
                    msgPtr.count,
                    &macT,
                    macTCount,
                    &outLen
                )
            }
        }
        return Data(macT)
    }
}
