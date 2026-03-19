// MARK: - LoggerProtocol.swift
//
// Pluggable logging abstraction. Not used internally by SessionManagerEngine
// (which uses os.log directly), but available for consumers to implement
// custom logging backends (e.g. forwarding to Datadog, Sentry, etc.).

import Foundation
#if canImport(OSLog)
import OSLog
#endif

/// Cross-platform, minimal logging level used by the protocol.
public enum LogLevel: Int, Comparable, CaseIterable, Sendable {
    case trace = 0, debug, info, notice, warning, error, fault

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

public protocol LoggerProtocol: Sendable {
    /// Metadata key type (default: String)
    associatedtype Key: Hashable
    /// Metadata value type (must be convertible to string for sinks)
    associatedtype Value

    /// Core logging entry point. Implementations must be thread-safe.
    func log(
        level: LogLevel,
        _ message: @autoclosure @Sendable () -> String,
        metadata: [Key: Value]?,
        file: String,
        function: String,
        line: UInt
    )

    /// Ask logger if the given level is enabled. Default implementation returns true.
    func isEnabled(_ level: LogLevel) -> Bool
}

public extension LoggerProtocol {
    // default metadata key/value types convenience when not specialized
    typealias DefaultKey = String
    typealias DefaultValue = CustomStringConvertible

    // default source info values
    func log(
        level: LogLevel,
        _ message: @autoclosure @Sendable () -> String,
        metadata: [Key: Value]? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        guard isEnabled(level) else { return }
        log(level: level, message(), metadata: metadata, file: file, function: function, line: line)
    }

    func isEnabled(_ level: LogLevel) -> Bool { true }

    // Convenience shorthands
    func trace(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .trace, msg(), metadata: metadata, file: file, function: function, line: line) }
    func debug(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .debug, msg(), metadata: metadata, file: file, function: function, line: line) }
    func info(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .info, msg(), metadata: metadata, file: file, function: function, line: line) }
    func notice(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .notice, msg(), metadata: metadata, file: file, function: function, line: line) }
    func warning(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .warning, msg(), metadata: metadata, file: file, function: function, line: line) }
    func error(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .error, msg(), metadata: metadata, file: file, function: function, line: line) }
    func fault(_ msg: @autoclosure @Sendable () -> String, metadata: [Key: Value]? = nil, file: String = #fileID, function: String = #function, line: UInt = #line) { log(level: .fault, msg(), metadata: metadata, file: file, function: function, line: line) }
}

public struct AnyLogger<Key: Hashable, Value>: LoggerProtocol {
    private let _log: @Sendable (LogLevel, String, [Key: Value]?, String, String, UInt) -> Void
    private let _isEnabled: @Sendable (LogLevel) -> Bool

    public init(
        log: @Sendable @escaping (LogLevel, String, [Key: Value]?, String, String, UInt) -> Void,
        isEnabled: @Sendable @escaping (LogLevel) -> Bool
    ) {
        self._log = log
        self._isEnabled = isEnabled
    }

    public func log(level: LogLevel, _ message: @autoclosure @Sendable () -> String, metadata: [Key : Value]?, file: String, function: String, line: UInt) {
        _log(level, message(), metadata, file, function, line)
    }

    public func isEnabled(_ level: LogLevel) -> Bool { _isEnabled(level) }
}

public struct PrintLogger<Key: Hashable, Value>: LoggerProtocol {
    public var minLevel: LogLevel
    public var metadataFormatter:  (@Sendable ([Key: Value]) -> String)?

    public init(minLevel: LogLevel = .trace, metadataFormatter: (@Sendable ([Key: Value]) -> String)? = nil) {
        self.minLevel = minLevel
        self.metadataFormatter = metadataFormatter
    }

    public func isEnabled(_ level: LogLevel) -> Bool { level >= minLevel }

    public func log(level: LogLevel, _ message: @autoclosure () -> String, metadata: [Key : Value]?, file: String, function: String, line: UInt) {
        let metaString = metadata.map { metadataFormatter?($0) ?? ($0.map { "\($0.key)=\($0.value)" }.joined(separator: " ")) } ?? ""
        let msg = message()
        let shortFile = (file as NSString).lastPathComponent
        Swift.print("[\(level)] \(shortFile):\(line) \(function) — \(msg)\(metaString.isEmpty ? "" : " | \(metaString)")")
    }
}
