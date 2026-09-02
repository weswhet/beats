// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

import Darwin
import Foundation
import OSLog

// Keep these values stable. Filebeat integration tests can select the emitter
// records without having to infer a subsystem or category from the host.
private let primarySubsystem = "co.elastic.filebeat.unifiedlogs.e2e.primary"
private let secondarySubsystem = "co.elastic.filebeat.unifiedlogs.e2e.secondary"
private let emitterVersion = "1"
private let defaultRunID = "run-default"

private typealias ActivityBlock = @convention(block) () -> Void

// os_activity_initiate is a C macro and is not imported by the Swift OSLog
// module. The underscored entry point has been available since macOS 10.10,
// which covers the minimum deployment target used by this fixture.
@_silgen_name("_os_activity_initiate")
private func nativeActivityInitiate(
    _ dso: UnsafeMutableRawPointer?,
    _ description: UnsafePointer<CChar>,
    _ flags: UInt32,
    _ block: ActivityBlock
)

private struct Arguments {
    let runID: String
    let holdMilliseconds: UInt64
    let skipActivity: Bool
    let showHelp: Bool

    static func parse(_ arguments: ArraySlice<String>) throws -> Arguments {
        var runID = defaultRunID
        var holdMilliseconds: UInt64 = 0
        var skipActivity = false
        var showHelp = false

        var iterator = arguments.makeIterator()
        while let argument = iterator.next() {
            switch argument {
            case "--":
                // SwiftPM inserts an option delimiter before executable
                // arguments. Accept it so the fixture works through both
                // `swift run` and XcodeBuildMCP.
                continue
            case "--run-id":
                guard let value = iterator.next(), !value.isEmpty else {
                    throw UsageError.missingValue("--run-id")
                }
                guard !value.contains("\n"), !value.contains("\r") else {
                    throw UsageError.invalidValue("--run-id cannot contain a newline")
                }
                runID = value
            case "--hold-ms":
                guard let value = iterator.next(), let milliseconds = UInt64(value) else {
                    throw UsageError.invalidValue("--hold-ms expects a non-negative integer")
                }
                holdMilliseconds = milliseconds
            case "--no-activity":
                skipActivity = true
            case "--help", "-h":
                showHelp = true
            default:
                throw UsageError.unknownOption(argument)
            }
        }

        return Arguments(
            runID: runID,
            holdMilliseconds: holdMilliseconds,
            skipActivity: skipActivity,
            showHelp: showHelp
        )
    }
}

private enum UsageError: LocalizedError {
    case missingValue(String)
    case invalidValue(String)
    case unknownOption(String)

    var errorDescription: String? {
        switch self {
        case .missingValue(let option):
            return "missing value for \(option)"
        case .invalidValue(let message):
            return message
        case .unknownOption(let option):
            return "unknown option \(option)"
        }
    }
}

private func usage() -> String {
    """
    Usage: unifiedlogs-emitter [--run-id ID] [--hold-ms MILLISECONDS] [--no-activity]

      --run-id ID       Public value included in every emitted record.
      --hold-ms N       Keep the process alive for N milliseconds after logging.
      --no-activity     Skip the activity-scoped records.
      --help            Show this help.

    The default run ID is \(defaultRunID). Pass a unique ID for each live run.
    """
}

private func emitLoggerRecords(runID: String) {
    guard #available(macOS 11.0, *) else {
        return
    }

    let logger = Logger(subsystem: primarySubsystem, category: "logger")
    let payloadLogger = Logger(subsystem: primarySubsystem, category: "payload")
    let secondaryLogger = Logger(subsystem: secondarySubsystem, category: "secondary")
    let structuredInteger = 4242
    let structuredString = "structured-string"
    let privateString = "private-value-\(runID)"
    let multiline = "line-one-\(runID)\nline-two\nline-three"

    logger.log(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=01 source=logger level=default"
    )
    logger.info(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=02 source=logger level=info"
    )
    logger.debug(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=03 source=logger level=debug"
    )
    logger.error(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=04 source=logger level=error"
    )
    logger.fault(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=05 source=logger level=fault"
    )

    payloadLogger.notice(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=06 source=logger payload=structured integer=\(structuredInteger, privacy: .public) string=\(structuredString, privacy: .public)"
    )
    payloadLogger.info(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=07 source=logger payload=private public-value=\(structuredString, privacy: .public) private-value=\(privateString, privacy: .private)"
    )
    payloadLogger.info(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=08 source=logger payload=multiline text=\(multiline, privacy: .public)"
    )
    secondaryLogger.notice(
        "run=\(runID, privacy: .public) emitter=swift-oslog-emitter version=\(emitterVersion, privacy: .public) sequence=09 source=logger subsystem=secondary category=secondary"
    )
}

private func emitLegacyRecords(runID: String) {
    let primaryLog = OSLog(subsystem: primarySubsystem, category: "os_log")
    let secondaryLog = OSLog(subsystem: secondarySubsystem, category: "legacy")
    let structuredInteger = 4242
    let structuredString = "structured-string"
    let privateString = "private-value-\(runID)"
    let multiline = "line-one-\(runID)\nline-two\nline-three"

    os_log(
        .default,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=10 source=os_log level=default",
        runID,
        emitterVersion
    )
    os_log(
        .info,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=11 source=os_log level=info",
        runID,
        emitterVersion
    )
    os_log(
        .debug,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=12 source=os_log level=debug",
        runID,
        emitterVersion
    )
    os_log(
        .error,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=13 source=os_log level=error",
        runID,
        emitterVersion
    )
    os_log(
        .fault,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=14 source=os_log level=fault",
        runID,
        emitterVersion
    )
    os_log(
        .default,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=15 source=os_log payload=structured integer=%{public}ld string=%{public}@",
        runID,
        emitterVersion,
        structuredInteger,
        structuredString
    )
    os_log(
        .info,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=16 source=os_log payload=private public-value=%{public}@ private-value=%{private}@",
        runID,
        emitterVersion,
        structuredString,
        privateString
    )
    os_log(
        .info,
        log: primaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=17 source=os_log payload=multiline text=%{public}@",
        runID,
        emitterVersion,
        multiline
    )
    os_log(
        .default,
        log: secondaryLog,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=18 source=os_log subsystem=secondary category=legacy",
        runID,
        emitterVersion
    )
}

private func emitSignposts(runID: String) {
    let signpostLog = OSLog(subsystem: primarySubsystem, category: "signpost")
    let signpostID = OSSignpostID(log: signpostLog)

    os_signpost(
        .begin,
        log: signpostLog,
        name: "FilebeatEmitterInterval",
        signpostID: signpostID,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=19 source=signpost marker=begin",
        runID,
        emitterVersion
    )
    os_signpost(
        .event,
        log: signpostLog,
        name: "FilebeatEmitterEvent",
        signpostID: signpostID,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=20 source=signpost marker=event",
        runID,
        emitterVersion
    )
    os_signpost(
        .end,
        log: signpostLog,
        name: "FilebeatEmitterInterval",
        signpostID: signpostID,
        "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=21 source=signpost marker=end",
        runID,
        emitterVersion
    )
}

private func emitActivityRecords(runID: String) {
    let activityLogger = OSLog(subsystem: primarySubsystem, category: "activity")
    var dsoToken: UInt8 = 0

    let block: ActivityBlock = {
        os_log(
            .default,
            log: activityLogger,
            "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=22 source=activity marker=begin",
            runID,
            emitterVersion
        )
        os_log(
            .info,
            log: activityLogger,
            "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=23 source=activity marker=body",
            runID,
            emitterVersion
        )
        os_log(
            .default,
            log: activityLogger,
            "run=%{public}@ emitter=swift-oslog-emitter version=%{public}@ sequence=24 source=activity marker=end",
            runID,
            emitterVersion
        )
    }

    "filebeat.unifiedlogs.emitter.activity".withCString { description in
        withUnsafeMutablePointer(to: &dsoToken) { dso in
            nativeActivityInitiate(UnsafeMutableRawPointer(dso), description, 0, block)
        }
    }
}

private func emitAllRecords(arguments: Arguments) {
    print("EMITTER_START run_id=\(arguments.runID) subsystem=\(primarySubsystem) secondary_subsystem=\(secondarySubsystem)")
    emitLoggerRecords(runID: arguments.runID)
    emitLegacyRecords(runID: arguments.runID)
    emitSignposts(runID: arguments.runID)
    if !arguments.skipActivity {
        emitActivityRecords(runID: arguments.runID)
    }
    if arguments.holdMilliseconds > 0 {
        Thread.sleep(forTimeInterval: Double(arguments.holdMilliseconds) / 1000.0)
    }
    print("EMITTER_DONE run_id=\(arguments.runID) sequences=01-24 activity=\(!arguments.skipActivity)")
}

do {
    let arguments = try Arguments.parse(CommandLine.arguments.dropFirst())
    if arguments.showHelp {
        print(usage())
    } else {
        emitAllRecords(arguments: arguments)
    }
} catch {
    fputs("unifiedlogs-emitter: \(error.localizedDescription)\n\(usage())\n", stderr)
    exit(EXIT_FAILURE)
}
