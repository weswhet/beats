// swift-tools-version: 5.9

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

import PackageDescription

let package = Package(
    name: "UnifiedLogsEmitter",
    platforms: [.macOS(.v10_15)],
    products: [
        .executable(name: "unifiedlogs-emitter", targets: ["unifiedlogs-emitter"]),
    ],
    targets: [
        .executableTarget(
            name: "unifiedlogs-emitter",
            path: ".",
            exclude: ["README.md"],
            sources: ["main.swift"]
        ),
    ]
)
