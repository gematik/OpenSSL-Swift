// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "OpenSSL-Swift",
        platforms: [
        .iOS(.v13), .macOS(.v12)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "OpenSSL-Swift",
            targets: ["OpenSSL"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .binaryTarget(
            name: "OpenSSL",
            url: "https://github.com/gematik/OpenSSL-Swift/releases/download/4.3.1/OpenSSL.xcframework.zip",
            checksum: "7b78e3de6adec618bfa294013e556b01e9c7d5476af3c8fcc40909042ca8c296"
        )
    ]
)
