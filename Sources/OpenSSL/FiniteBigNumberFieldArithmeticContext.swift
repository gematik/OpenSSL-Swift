//
// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
//

@_implementationOnly import COpenSSL
import Foundation

/// A context for performing mathematical operations on BigNumber over a finite field.
///
/// A common part of elliptic curve mathematics is to perform arithmetic operations over a finite field. These require
/// performing modular arithmetic, and cannot be processed in the same way as regular math on these integers.
///
/// Most operations we perform over finite fields are part of repeated, larger arithmetic operations, so this object
/// also manages the lifetime of a `BN_CTX`. While `BN_CTX` is a silly data type, it does still have the effect of
/// caching existing `BIGNUM`s, so it's not a terrible idea to use it here.
@usableFromInline
class FiniteBigNumberFieldArithmeticContext {
    private var fieldSize: BigNumber
    private var bnCtx: OpaquePointer

    @usableFromInline
    init(fieldSize: BigNumber) throws {
        self.fieldSize = fieldSize
        guard let bnCtx = BN_CTX_new() else {
            throw OpenSSLError(name: "Unable to allocate BN_CTX_new")
        }
        BN_CTX_start(bnCtx)
        self.bnCtx = bnCtx
    }

    deinit {
        BN_CTX_end(bnCtx)
        BN_CTX_free(bnCtx)
    }
}

// MARK: - Arithmetic operations

extension FiniteBigNumberFieldArithmeticContext {
    @usableFromInline
    func subtract(_ x: BigNumber, from y: BigNumber) -> BigNumber? { // swiftlint:disable:this identifier_name
        let output = BigNumber()

        let resultCode = x.withUnsafeBignumPointer { xPointer in
            y.withUnsafeBignumPointer { yPointer in
                self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                    output.withUnsafeBignumPointer { outputPointer in
                        // Note the order of y and x.
                        BN_mod_sub(
                            outputPointer,
                            yPointer,
                            xPointer,
                            fieldSizePointer,
                            self.bnCtx
                        )
                    }
                }
            }
        }

        guard resultCode == 1 else {
            return nil
        }

        return output
    }
}
