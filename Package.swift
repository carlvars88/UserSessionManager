// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SessionManager",
    platforms: [
        .macOS(.v11),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "SessionManager",
            targets: ["SessionManager"]),
        .library(
            name: "IdentityProviders",
            targets: ["IdentityProviders"]),
    ],
    targets: [
        .target(
            name: "SessionManager"),
        .target(
            name: "IdentityProviders",
            dependencies: ["SessionManager"]),
        .testTarget(
            name: "SessionManagerTests",
            dependencies: ["SessionManager"]
        ),
    ]
)
