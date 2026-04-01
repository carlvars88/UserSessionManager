// MARK: - LoggerProtocol.swift
//
// Pluggable logging abstraction wired into SessionManagerEngine via
// SessionManagerConfiguration.logger. The default backend is os.log.
// Swap it out to forward to SwiftLog, Datadog, Sentry, etc.

import Foundation
#if canImport(OSLog)
import OSLog
#endif

// MARK: - LogLevel

/// Severity levels for session manager log messages, ordered from least to most severe.
public enum LogLevel: Int, Comparable, CaseIterable, Sendable {
    case trace = 0, debug, info, notice, warning, error, fault

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

// MARK: - SessionLogger

/// Logging contract for the session manager.
///
/// Implement this protocol to forward session events to your preferred
/// logging system (SwiftLog, Datadog, Sentry, etc.):
///
/// ```swift
/// struct DatadogLogger: SessionLogger {
///     func log(level: LogLevel, _ message: @autoclosure () -> String,
///              file: String, function: String, line: UInt) {
///         Datadog.logger.log(level: level.ddLevel, message: message())
///     }
/// }
///
/// let config = SessionManagerConfiguration(logger: DatadogLogger())
/// ```
///
/// The engine pre-filters messages by `SessionManagerConfiguration.logLevel`
/// before calling `log(...)`, so implementations do not need to repeat
/// the threshold check. Override `isEnabled(_:)` only when the backend
/// has its own dynamic enable/disable mechanism.
public protocol SessionLogger: Sendable {

    /// Write one log entry.
    ///
    /// The `message` closure is evaluated lazily — only call it if the
    /// message will actually be recorded.
    func log(
        level:    LogLevel,
        _ message: @autoclosure @Sendable () -> String,
        file:     String,
        function: String,
        line:     UInt
    )

    /// Return `false` to suppress a level entirely.
    /// The default implementation returns `true` for all levels.
    func isEnabled(_ level: LogLevel) -> Bool
}

public extension SessionLogger {
    /// Default: all levels enabled.
    func isEnabled(_ level: LogLevel) -> Bool { true }

    // Convenience shorthands
    func trace(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line)   { guard isEnabled(.trace)   else { return }; log(level: .trace,   msg(), file: file, function: function, line: line) }
    func debug(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line)   { guard isEnabled(.debug)   else { return }; log(level: .debug,   msg(), file: file, function: function, line: line) }
    func info(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line)    { guard isEnabled(.info)    else { return }; log(level: .info,    msg(), file: file, function: function, line: line) }
    func notice(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line)  { guard isEnabled(.notice)  else { return }; log(level: .notice,  msg(), file: file, function: function, line: line) }
    func warning(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line) { guard isEnabled(.warning) else { return }; log(level: .warning, msg(), file: file, function: function, line: line) }
    func error(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line)   { guard isEnabled(.error)   else { return }; log(level: .error,   msg(), file: file, function: function, line: line) }
    func fault(_ msg: @autoclosure @Sendable () -> String, file: String = #fileID, function: String = #function, line: UInt = #line)   { guard isEnabled(.fault)   else { return }; log(level: .fault,   msg(), file: file, function: function, line: line) }
}

// MARK: - OSLogger

/// A `SessionLogger` backed by `os.log`.
///
/// Messages appear in Console.app and the Xcode console. This is the
/// default logger used by `SessionManagerConfiguration`.
///
/// ```swift
/// // Default subsystem and category
/// OSLogger()
///
/// // Custom subsystem and category for filtering in Console.app
/// OSLogger(subsystem: "com.myapp", category: "Auth")
/// ```
public struct OSLogger: SessionLogger {

    #if canImport(OSLog)
    private let logger: Logger
    #endif

    /// - Parameters:
    ///   - subsystem: The reverse-DNS subsystem identifier. Defaults to the bundle identifier.
    ///   - category: The log category. Defaults to `"SessionManager"`.
    public init(
        subsystem: String = Bundle.main.bundleIdentifier ?? "app",
        category:  String = "SessionManager"
    ) {
        #if canImport(OSLog)
        self.logger = Logger(subsystem: subsystem, category: category)
        #endif
    }

    public func log(
        level:    LogLevel,
        _ message: @autoclosure @Sendable () -> String,
        file:     String,
        function: String,
        line:     UInt
    ) {
        #if canImport(OSLog)
        let msg = message()
        switch level {
        case .trace, .debug: logger.debug("\(msg, privacy: .public)")
        case .info:          logger.info("\(msg, privacy: .public)")
        case .notice:        logger.notice("\(msg, privacy: .public)")
        case .warning:       logger.warning("\(msg, privacy: .public)")
        case .error:         logger.error("\(msg, privacy: .public)")
        case .fault:         logger.critical("\(msg, privacy: .public)")
        }
        #endif
    }
}

// MARK: - PrintLogger

/// A `SessionLogger` that writes to stdout.
///
/// Useful during development and in unit tests. Not recommended for
/// production — use `OSLogger` or a custom backend instead.
///
/// ```swift
/// let config = SessionManagerConfiguration(
///     logLevel: .debug,
///     logger:   PrintLogger(minLevel: .debug)
/// )
/// ```
public struct PrintLogger: SessionLogger {

    /// The minimum level this logger will emit.
    public let minLevel: LogLevel

    /// - Parameter minLevel: Messages below this level are suppressed. Defaults to `.trace`.
    public init(minLevel: LogLevel = .trace) {
        self.minLevel = minLevel
    }

    public func isEnabled(_ level: LogLevel) -> Bool { level >= minLevel }

    public func log(
        level:    LogLevel,
        _ message: @autoclosure @Sendable () -> String,
        file:     String,
        function: String,
        line:     UInt
    ) {
        let shortFile = file.split(separator: "/").last.map(String.init) ?? file
        Swift.print("[\(level)] \(shortFile):\(line) — \(message())")
    }
}
