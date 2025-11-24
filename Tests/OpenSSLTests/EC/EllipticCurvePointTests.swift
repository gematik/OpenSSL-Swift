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
@testable import OpenSSL
import XCTest

final class EllipticCurvePointTests: XCTestCase {
    func testInitAndExportFromUncompressedRawData() throws {
        // given
        let pointUncompressedRawData =
            try Data(
                hex: "0435AAD48B06E2B1B10EE09DBCE9C80ABCDDD139F9BDC35EFD7C7832085B87F7744A2B7A13149AC71A252DB814214483EBB4EB6635FC375A7361A5D5C2E14DBC8F" // swiftlint:disable:this line_length
            )
        let pointCompressedRawData =
            try Data(
                hex: "0335AAD48B06E2B1B10EE09DBCE9C80ABCDDD139F9BDC35EFD7C7832085B87F774" // swiftlint:disable:this line_length
            )

        // when
        let ecPoint = try EllipticCurvePoint<BrainpoolP256r1.Curve>(raw: pointUncompressedRawData)
        let exportUncompressed = try ecPoint.export(pointConversion: .uncompressed)
        let exportCompressed = try ecPoint.export(pointConversion: .compressed)

        // then
        XCTAssertEqual(exportUncompressed, pointUncompressedRawData)
        XCTAssertEqual(exportCompressed, pointCompressedRawData)
    }

    func testInitFromRawData_compressed() throws {
        // given
        let pointUncompressedRawData =
            try Data(
                hex: "0435AAD48B06E2B1B10EE09DBCE9C80ABCDDD139F9BDC35EFD7C7832085B87F7744A2B7A13149AC71A252DB814214483EBB4EB6635FC375A7361A5D5C2E14DBC8F" // swiftlint:disable:this line_length
            )
        let pointCompressedRawData =
            try Data(
                hex: "0335AAD48B06E2B1B10EE09DBCE9C80ABCDDD139F9BDC35EFD7C7832085B87F774" // swiftlint:disable:this line_length
            )

        // when
        let ecPoint = try EllipticCurvePoint<BrainpoolP256r1.Curve>(raw: pointCompressedRawData)
        let exportUncompressed = try ecPoint.export(pointConversion: .uncompressed)
        let exportCompressed = try ecPoint.export(pointConversion: .compressed)

        // then
        XCTAssertEqual(exportUncompressed, pointUncompressedRawData)
        XCTAssertEqual(exportCompressed, pointCompressedRawData)
    }

    func testAddAnotherPoint() throws {
        // given
        let point1RawData =
            try Data(
                hex: "0435AAD48B06E2B1B10EE09DBCE9C80ABCDDD139F9BDC35EFD7C7832085B87F7744A2B7A13149AC71A252DB814214483EBB4EB6635FC375A7361A5D5C2E14DBC8F" // swiftlint:disable:this line_length
            )
        let point2RawData =
            try Data(
                hex: "04941DDF52912A31313BD2A9E88A10691403D7B5CB810EA3AF2D8393C3EC380D3F385F7F3E6CF7B5A7CC0CA7AA9E573FA1849B664F32E417C5A4EA1D10BF5F5B8A" // swiftlint:disable:this line_length
            )
        let point1 = try EllipticCurvePoint<BrainpoolP256r1.Curve>(raw: point1RawData)
        let point2 = try EllipticCurvePoint<BrainpoolP256r1.Curve>(raw: point2RawData)

        // when
        let point = try point1.add(point2)
        let export = try point.export(pointConversion: .uncompressed)

        // then
        let expected =
            try Data(
                hex: "047F6F0BB04F8CE6E67B93DB8B61929CB211C0FEF9602D9CAC431B0DFF081F89BC3BE2DD1F03BB1D46947CDB2F11F77DDC9E9C7211502334A3450591EC57900A86" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(export, expected)
    }

    func testInitViaMultiplyScalarWithBasePoint() throws {
        // given
        let scalar = try BigNumber(bytes: try Data(hex: "6B4C371D20A352D570183879FE1EEB63"))

        // when
        let point = try EllipticCurvePoint<BrainpoolP256r1.Curve>(multiplyWithBasePoint: scalar)
        let export = try point.export(pointConversion: .uncompressed)

        // then
        let expected =
            try Data(
                hex:
                "04821EADCCD4EFAB8D2C6608ED4E0303DC5FF1074D688EA4A7D3BD6B9D2B20D5C87965BF640347DE95E7CC467BA230F0ACEDF507068692A2F415C4DC0ABA69CFFB" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(export, expected)
    }

    func testMultiplicationWithEllipticCurvePoint() throws {
        // given
        let scalar =
            try BigNumber(bytes: try Data(hex: "0162AD399C4603B47A878BFAFB81CA17317D6649FEA0B3FE079329514BC6319FE4"))
        let point1Raw =
            try Data(
                hex: "04662553C7EBD0466473FB3AF925EC89CE4F4EEB89FFB8AECA4CB1BD6B55460CBBA6DF467A24DF394AAA230B7B630E35B9E89350F3E78D24E40F91F29B8E16D47C" // swiftlint:disable:this line_length
            )
        let point1 = try EllipticCurvePoint<BrainpoolP256r1.Curve>(raw: point1Raw)

        // when
        let product = try point1.multiply(scalar)
        let export = try product.export(pointConversion: .uncompressed)

        // then
        let expected =
            try Data(
                hex: "044241F43161DB2400704509015D66EDB85FA8236157C4D11BDB4CA258000434B98FE93ABCD6F172B1678933D7CC7B17C698664EF36AA527E158979C1A4D3B191B" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(export, expected)
    }

    func testMultiplyWithScalar() throws {
        // given
        let scalar =
            try BigNumber(bytes: try Data(hex: "0162AD399C4603B47A878BFAFB81CA17317D6649FEA0B3FE079329514BC6319FE4"))
        let point1Raw =
            try Data(
                hex: "04662553C7EBD0466473FB3AF925EC89CE4F4EEB89FFB8AECA4CB1BD6B55460CBBA6DF467A24DF394AAA230B7B630E35B9E89350F3E78D24E40F91F29B8E16D47C" // swiftlint:disable:this line_length
            )
        let point1 = try EllipticCurvePoint<BrainpoolP256r1.Curve>(raw: point1Raw)

        // when
        let product = try point1.multiply(scalar)
        let export = try product.export(pointConversion: .uncompressed)

        // then
        let expected =
            try Data(
                hex: "044241F43161DB2400704509015D66EDB85FA8236157C4D11BDB4CA258000434B98FE93ABCD6F172B1678933D7CC7B17C698664EF36AA527E158979C1A4D3B191B" // swiftlint:disable:this line_length
            )
        XCTAssertEqual(export, expected)
    }
}
