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
    public static func aes128cbc(key: Data, data: Data) throws -> Data {
        let byteCount = 16
        guard key.count == byteCount else {
            throw OpenSSLError(name: "Key length invalid for CMAC calculation")
        }
        var macT = [UInt8](repeating: 0x0, count: byteCount)
        var macTCount = byteCount

        let ctx: OpaquePointer = CMAC_CTX_new()
        defer {
            CMAC_CTX_free(ctx)
        }

        try key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) in
            try data.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) in
                guard let keyPtrBaseAddress = keyPtr.baseAddress,
                      let msgPtrBaseAddress = msgPtr.baseAddress else {
                    throw OpenSSLError(name: "Error deriving CMAC")
                }
                CMAC_Init(ctx, keyPtrBaseAddress, byteCount, EVP_aes_128_cbc(), nil)
                CMAC_Update(ctx, msgPtrBaseAddress, msgPtr.count)
                CMAC_Final(ctx, &macT, &macTCount)
            }
        }
        return Data(macT)
    }
}
