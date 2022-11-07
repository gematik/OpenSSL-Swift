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

import Foundation

/// The BrainpoolP256r1 Elliptic Curve.
///
/// [REQ:gemSpec_Krypt:GS-A_4361]
/// [REQ:gemSpec_Krypt:GS-A_4357]
public enum BrainpoolP256r1 {}

extension BrainpoolP256r1 {
    struct Curve: ECCurve {
        static var name: String = OpenSSLECGroup.Name.brainpoolP256r1.rawValue

        static var group: OpenSSLECGroup {
            guard let group = try? OpenSSLECGroup(curve: .brainpoolP256r1) else {
                preconditionFailure("BrainpoolP256r1 OpenSSL ECGroup could not be initialized")
            }
            return group
        }
    }
}
