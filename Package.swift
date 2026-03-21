// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FreeFlow",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "FreeFlowCore", targets: ["FreeFlowCore"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "FreeFlowCore",
            path: "FreeFlow/Sources/Core",
            resources: [
                .copy("Lexical/profiles"),
            ]
        ),
        .testTarget(
            name: "FreeFlowTests",
            dependencies: ["FreeFlowCore"],
            path: "FreeFlow/Tests"
        ),
    ]
)
