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
