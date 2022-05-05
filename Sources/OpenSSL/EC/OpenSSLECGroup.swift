//
//  Copyright (c) 2022 gematik GmbH
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

/// Elliptic-Curve protocol
public protocol ECCurve {
    /// Elliptic-Curve group information
    static var group: OpenSSLECGroup { get }
}

/// Elliptic-Curve information in accordance with OpenSSL
public class OpenSSLECGroup {
    @usableFromInline let curve: OpaquePointer

    /// Initialize a Curve by `OpenSSLECGroup.Name`
    ///
    /// - Parameter curve: curve name
    /// - Throws: `OpenSSLError` when the curve could not be found by the underlying OpenSSL implementation
    public init(curve: Name) throws {
        guard let opensslGroup = EC_GROUP_new_by_curve_name(curve.nid) else {
            throw OpenSSLError(name: "EC Curve not found: [\(curve.nid)]")
        }
        self.curve = opensslGroup
    }

    /// De-init OpenSSLECGroup
    deinit {
        EC_GROUP_free(curve)
    }

    @inlinable
    func withUnsafeGroupPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(curve)
    }
}

extension OpenSSLECGroup {
    /// Curves
    public enum Name {
        /// BrainpoolP256r1 as defined in https://tools.ietf.org/html/rfc5639
        case brainpoolP256r1

        var nid: CInt {
            switch self {
            // [REQ:gemSpec_Krypt:GS-A_4361] (For now only) BrainpoolP256r1 curve support
            // [REQ:gemSpec_Krypt:GS-A_4357] (For now only) BrainpoolP256r1 curve support
            case .brainpoolP256r1: return NID_brainpoolP256r1
            }
        }
    }
}

extension OpenSSLECGroup {
    @usableFromInline var coordinateByteCount: Int {
        (Int(EC_GROUP_get_degree(curve)) + 7) / 8
    }

    @usableFromInline
    func makeUnsafeOwnedECKey() throws -> OpaquePointer {
        guard let key = EC_KEY_new(),
              EC_KEY_set_group(key, curve) == 1 else {
            throw OpenSSLError(name: "EC key initialization error")
        }

        return key
    }

    @usableFromInline var order: BigNumber {
        // Groups must have an order.
        let baseOrder = EC_GROUP_get0_order(curve) as BIGNUM
        return BigNumber(copying: baseOrder)
    }

    /// An elliptic curve can be represented in a Weierstrass form: `y² = x³ + ax + b`. This
    /// property provides the values of a and b on the curve.
    @usableFromInline var weierstrassCoefficients: (field: BigNumber, a: BigNumber, b: BigNumber) {
        // swiftlint:disable:previous large_tuple
        let field = BigNumber()
        let a = BigNumber() // swiftlint:disable:this identifier_name
        let b = BigNumber() // swiftlint:disable:this identifier_name

        let number = field.withUnsafeBignumPointer { fieldPtr in
            a.withUnsafeBignumPointer { aPtr in
                b.withUnsafeBignumPointer { bPtr in
                    EC_GROUP_get_curve(self.curve, fieldPtr, aPtr, bPtr, nil)
                }
            }
        }
        precondition(number == 1, "Unable to extract curve weierstrass parameters")

        return (field: field, a: a, b: b)
    }
}
