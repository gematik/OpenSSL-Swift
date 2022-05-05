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

@usableFromInline
class EllipticCurvePoint {
    @usableFromInline var point: OpaquePointer

    init(point: OpaquePointer) {
        self.point = point
    }

    /// Perform a point addition with the two points on the given curve
    ///
    /// - Parameters:
    ///   - summand1: first `EllipticCurvePoint`
    ///   - summand2: second `EllipticCurvePoint`
    ///   - group: curve as `OpenSSLECGroup`
    /// - Throws: `OpenSSLError`
    @usableFromInline
    init(add summand1: EllipticCurvePoint, to summand2: EllipticCurvePoint, on group: OpenSSLECGroup) throws {
        let point: OpaquePointer = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = EC_POINT_new(groupPtr) else {
                throw OpenSSLError(name: "EC_POINT internal error")
            }
            return pointPtr
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try summand1.withPointPointer { summand1Ptr in
                try summand2.withPointPointer { summand2Ptr in
                    guard EC_POINT_add(groupPtr, point, summand1Ptr, summand2Ptr, nil) != 0 else {
                        EC_POINT_free(point)
                        throw OpenSSLError(name: "EC_POINT internal error")
                    }
                }
            }
        }
        self.point = point
    }

    /// Multiply a scalar with a curve's base point.
    ///
    /// - Parameters:
    ///   - scalar: `BigNumber` to multiply the base point with
    ///   - group: curve as `OpenSSLECGroup`
    /// - Throws: `OpenSSLError`
    @usableFromInline
    init(multiplying scalar: BigNumber, on group: OpenSSLECGroup) throws {
        let point: OpaquePointer = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = EC_POINT_new(groupPtr) else {
                throw OpenSSLError(name: "EC_POINT internal error")
            }
            return pointPtr
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try scalar.withUnsafeBignumPointer { bigNumPtr in
                guard EC_POINT_mul(groupPtr, point, bigNumPtr, nil, nil, nil) != 0 else {
                    EC_POINT_free(point)
                    throw OpenSSLError(name: "EC_POINT internal error")
                }
            }
        }
        self.point = point
    }

    /// Multiply a scalar with a point.
    ///
    /// - Parameters:
    ///   - scalar: `BigNumber` to multiply the other point with
    ///   - otherPoint: `EllipticCurvePoint`
    ///   - group: curve as `OpenSSLECGroup`
    /// - Throws: `OpenSSLError`
    @usableFromInline
    init(multiplying scalar: BigNumber, with otherPoint: EllipticCurvePoint, on group: OpenSSLECGroup) throws {
        let point: OpaquePointer = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = EC_POINT_new(groupPtr) else {
                throw OpenSSLError(name: "EC_POINT internal error")
            }
            return pointPtr
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try scalar.withUnsafeBignumPointer { bigNumPtr in
                guard EC_POINT_mul(groupPtr, point, nil, otherPoint.point, bigNumPtr, nil) != 0 else {
                    EC_POINT_free(point)
                    throw OpenSSLError(name: "EC_POINT internal error")
                }
            }
        }
        self.point = point
    }

    deinit {
        EC_POINT_free(point)
    }

    func export(using compression: point_conversion_form_t, group: OpenSSLECGroup) -> Data? {
        var buffer: UnsafeMutablePointer<UInt8>?
        let size = EC_POINT_point2buf(group.curve, point, compression, &buffer, nil)
        guard size > 0, let safeBuffer = buffer else {
            return nil
        }
        return Data(bytesNoCopy: safeBuffer, count: size, deallocator: .free)
    }
}

extension EllipticCurvePoint {
    @usableFromInline
    func withPointPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(point)
    }
}

extension EllipticCurvePoint {
    @usableFromInline
    func affineCoordinates(group: OpenSSLECGroup) throws -> (x: BigNumber, y: BigNumber) {
        let x = BigNumber() // swiftlint:disable:this identifier_name
        let y = BigNumber() // swiftlint:disable:this identifier_name

        try x.withUnsafeBignumPointer { xPtr in
            try y.withUnsafeBignumPointer { yPtr in
                try group.withUnsafeGroupPointer { groupPtr in
                    guard EC_POINT_get_affine_coordinates(groupPtr, point, xPtr, yPtr, nil) == 1
                    else {
                        throw OpenSSLError(name: "EC_POINT get affine coordinates GFp failed")
                    }
                }
            }
        }

        return (x: x, y: y)
    }
}
