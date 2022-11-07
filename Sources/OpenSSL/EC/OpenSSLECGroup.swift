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
    /// Name of the ECCurve (group) in OpenSSL (e.g. "brainpoolP256r1", "P-256", etc ...)
    static var name: String { get }
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
    public enum Name: String {
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
}
