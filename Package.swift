// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "IDmeWebVerify",
    platforms: [
        .iOS(.v10)
    ],
    products: [
        .library(name: "IDmeWebVerify", targets: ["IDmeWebVerify"])
    ],
    dependencies: [
        .package(name: "KeychainSwift",
                 url: "https://github.com/evgenyneu/keychain-swift.git", .exact("20.0.0")),
    ],
    targets: [
        .target(
            name: "IDmeWebVerify",
            dependencies: ["KeychainSwift"],
            path: "Source")
    ]
)
