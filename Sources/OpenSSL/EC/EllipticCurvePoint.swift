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

@usableFromInline
class EllipticCurvePoint<Curve: ECCurve> {
    let point: OpaquePointer // internally EC_POINT is used

    init(point: OpaquePointer) {
        self.point = point
    }

    /// Initialize an `EllipticCurvePoint` from raw data in un-/compressed encoding.
    ///
    /// - Parameter raw: Can be either in compressed (0x02 / 0x03) or uncompressed (0x04) encoding.
    /// - Throws: OpenSSLError
    /// - Note: No check whether the encoded point actually lies on the curve is employed during initialisation.
    init(raw: Data) throws {
        point = try raw.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> OpaquePointer in
            let group = Curve.group
            let point = EC_POINT_new(group.curve)
            guard let bufferPointer = buffer.bindMemory(to: UInt8.self).baseAddress else {
                throw OpenSSLError(name: "EC_POINT data unavailable")
            }

            guard
                EC_POINT_oct2point(group.curve, point, bufferPointer, buffer.count, nil) == 1,
                let point = point
            else {
                throw OpenSSLError(name: "Incorrect EC_POINT encoding")
            }
            return point
        }
    }

    var group: OpenSSLECGroup {
        Curve.group
    }

    deinit {
        EC_POINT_free(point)
    }

    enum PointConversion {
        case uncompressed
        case compressed
    }

    func export(pointConversion: PointConversion) throws -> Data {
        let group = Curve.group
        var buffer: UnsafeMutablePointer<UInt8>?
        let pointConversionForm: point_conversion_form_t
        switch pointConversion {
        case .uncompressed: pointConversionForm = POINT_CONVERSION_UNCOMPRESSED
        case .compressed: pointConversionForm = POINT_CONVERSION_COMPRESSED
        }
        let size = EC_POINT_point2buf(group.curve, point, pointConversionForm, &buffer, nil)
        guard size > 0, let safeBuffer = buffer else {
            throw OpenSSLError(name: "Error exporting encoded data from EllipticCurvePoint")
        }
        return Data(bytesNoCopy: safeBuffer, count: size, deallocator: .free)
    }

    /// Perform a point addition with the two points on the given curve
    ///
    /// - Parameter other: the `EllipticCurvePoint` to be added
    /// - Returns: Sum of the addition as `EllipticCurvePoint`
    /// - Throws: `OpenSSLError`
    func add(_ other: EllipticCurvePoint) throws -> EllipticCurvePoint {
        let sumPoint: OpaquePointer = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = EC_POINT_new(groupPtr) else {
                throw OpenSSLError(name: "EC_POINT internal error")
            }
            return pointPtr
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try other.withPointPointer { otherPtr in
                guard
                    EC_POINT_add(groupPtr, sumPoint, point, otherPtr, nil) == 1
                else {
                    EC_POINT_free(sumPoint)
                    throw OpenSSLError(name: "EC_POINT internal error")
                }
            }
        }
        return EllipticCurvePoint(point: sumPoint)
    }

    /// Create an `EllipticCurvePoint` by multiplying a scalar with a curve's base point.
    ///
    /// - Parameters:
    ///   - scalar: `BigNumber` to multiply the base point with
    /// - Throws: `OpenSSLError`
    @usableFromInline
    init(multiplyWithBasePoint scalar: BigNumber) throws {
        let group = Curve.group
        let productPoint: OpaquePointer = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = EC_POINT_new(groupPtr) else {
                throw OpenSSLError(name: "EC_POINT internal error")
            }
            return pointPtr
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try scalar.withUnsafeBignumPointer { bigNumPtr in
                guard
                    EC_POINT_mul(groupPtr, productPoint, bigNumPtr, nil, nil, nil) != 0
                else {
                    EC_POINT_free(productPoint)
                    throw OpenSSLError(name: "EC_POINT internal error")
                }
            }
        }
        point = productPoint
    }

    /// Multiply a scalar with this point.
    ///
    /// - Parameter scalar: `BigNumber` to multiply the other point with
    /// - Returns: Product of the multiplication as `EllipticCurvePoint`
    /// - Throws: `OpenSSLError`
    func multiply(_ scalar: BigNumber) throws -> EllipticCurvePoint {
        let productPoint: OpaquePointer = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = EC_POINT_new(groupPtr) else {
                throw OpenSSLError(name: "EC_POINT internal error")
            }
            return pointPtr
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try scalar.withUnsafeBignumPointer { bigNumPtr in
                guard
                    EC_POINT_mul(groupPtr, productPoint, nil, point, bigNumPtr, nil) != 0
                else {
                    EC_POINT_free(productPoint)
                    throw OpenSSLError(name: "EC_POINT internal error")
                }
            }
        }
        return EllipticCurvePoint(point: productPoint)
    }
}

extension EllipticCurvePoint {
    @usableFromInline
    func withPointPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(point)
    }
}
