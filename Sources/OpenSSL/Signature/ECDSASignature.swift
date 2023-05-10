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

typealias ECDSA_SIG = OpaquePointer

class ECDSASignature {
    private let sig: ECDSA_SIG

    internal init(owningNoCopy signature: ECDSA_SIG) {
        sig = signature
    }

    convenience init<S: ECSignature>(signature: S) throws {
        try self.init(derRepresentation: signature.derRepresentation)
    }

    init(derRepresentation: Data) throws {
        sig = try derRepresentation.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            var bytesPtr = buffer.bindMemory(to: UInt8.self).baseAddress

            guard let rawSig = d2i_ECDSA_SIG(nil, &bytesPtr, buffer.count) else {
                throw OpenSSLError(name: "Signature not DER encoded")
            }
            return rawSig
        }
    }

    init(rawRepresentation: Data) throws {
        let half = rawRepresentation.count / 2
        let r = try BigNumber(bytes: rawRepresentation.prefix(half)) // swiftlint:disable:this identifier_name
        let s = try BigNumber(bytes: rawRepresentation.suffix(half)) // swiftlint:disable:this identifier_name
        guard let sig = ECDSA_SIG_new() else {
            throw OpenSSLError(name: "Signature could not be initialized")
        }
        try r.withUnsafeBignumPointer { rPtr in
            try s.withUnsafeBignumPointer { sPtr in
                // ECDSA_SIG_set0 takes ownership without copying the backing BIGNUM
                // Therefore we need to duplicate/copy them before passing them to `sig`
                // see: https://www.openssl.org/docs/man1.1.0/man3/ECDSA_SIG_set0.html
                guard let rCopy = BN_dup(rPtr) else {
                    ECDSA_SIG_free(sig)
                    throw OpenSSLError(name: "Could not copy [r]")
                }
                guard let sCopy = BN_dup(sPtr) else {
                    // free rCopy before throwing
                    BN_free(rCopy)
                    ECDSA_SIG_free(sig)
                    throw OpenSSLError(name: "Could not copy [s]")
                }

                if ECDSA_SIG_set0(sig, rCopy, sCopy) == 0 {
                    // Error. We still own the BIGNUMs, and must free them.
                    BN_free(rCopy)
                    BN_free(sCopy)
                    ECDSA_SIG_free(sig)
                    throw OpenSSLError(name: "Signature initialization failed")
                }
                // Success. We've passed BIGNUMs ownership successfully, so we don't free them.
            }
        }
        self.sig = sig
    }

    deinit {
        ECDSA_SIG_free(sig)
    }

    var derBytes: Data {
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let length = i2d_ECDSA_SIG(sig, &dataPtr)
        guard length > 0, let safeDataPtr = dataPtr else {
            return Data()
        }

        return Data(bytesNoCopy: safeDataPtr, count: Int(length), deallocator: .free)
    }

    var rawBytes: Data {
        var r, s: BIGNUM? // swiftlint:disable:this identifier_name
        /*  Accessor for r and s fields of ECDSA_SIG
         *  \param  sig  pointer to ECDSA_SIG pointer
         *  \param  pr   pointer to BIGNUM pointer for r (may be NULL)
         *  \param  ps   pointer to BIGNUM pointer for s (may be NULL)
         */
        ECDSA_SIG_get0(sig, &r, &s)
        guard let safeR = r, let safeS = s else {
            return Data()
        }
        return BigNumber(copying: safeR).rawBytes + BigNumber(copying: safeS).rawBytes
    }

    func withUnsafeSignaturePointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(sig)
    }
}
