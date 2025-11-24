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

typealias BIGNUM = OpaquePointer

@usableFromInline
class BigNumber {
    private let backing: BIGNUM

    init() {
        backing = BN_new()
    }

    init(owningNoCopy original: BIGNUM) {
        backing = original
    }

    deinit {
        BN_clear_free(backing)
    }

    var rawBytes: Data {
        withUnsafeBignumPointer { bignum in
            let size = (BN_num_bits(bignum) + 7) / 8
            var bytes = [UInt8](repeating: 0x0, count: Int(size))
            _ = BN_bn2bin(bignum, &bytes)
            return Data(bytes)
        }
    }
}

extension BigNumber {
    convenience init(bytes: ContiguousBytes) throws {
        self.init()

        let number: BIGNUM? = bytes.withUnsafeBytes { (bytesPointer: UnsafeRawBufferPointer) -> BIGNUM? in
            BN_bin2bn(bytesPointer.baseAddress?.assumingMemoryBound(to: UInt8.self), CInt(bytesPointer.count), backing)
        }
        guard number != nil else {
            throw OpenSSLError(name: "BIGNUM initialization error")
        }
    }

    convenience init(copying original: BIGNUM) {
        self.init()

        _ = withUnsafeBignumPointer { ptr in
            BN_copy(ptr, original)
        }
    }
}

extension BigNumber {
    func withUnsafeBignumPointer<T>(_ body: (BIGNUM) throws -> T) rethrows -> T {
        try body(backing)
    }
}

// MARK: - Equatable

extension BigNumber: Equatable {
    @inlinable
    static func ==(lhs: BigNumber, rhs: BigNumber) -> Bool {
        compare(lhs: lhs, rhs: rhs) == 0
    }
}

// MARK: - Comparable

extension BigNumber: Comparable {
    @inlinable
    static func <(lhs: BigNumber, rhs: BigNumber) -> Bool {
        compare(lhs: lhs, rhs: rhs) < 0
    }

    @inlinable
    static func <=(lhs: BigNumber, rhs: BigNumber) -> Bool {
        compare(lhs: lhs, rhs: rhs) <= 0
    }

    @inlinable
    static func >(lhs: BigNumber, rhs: BigNumber) -> Bool {
        compare(lhs: lhs, rhs: rhs) > 0
    }

    @inlinable
    static func >=(lhs: BigNumber, rhs: BigNumber) -> Bool {
        compare(lhs: lhs, rhs: rhs) >= 0
    }
}

extension BigNumber {
    @usableFromInline
    static func compare(lhs: BigNumber, rhs: BigNumber) -> CInt {
        lhs.withUnsafeBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                BN_cmp(lhsPtr, rhsPtr)
            }
        }
    }
}
