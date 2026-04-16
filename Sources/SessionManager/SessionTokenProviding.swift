// MARK: - Protocols/SessionTokenProviding.swift
//
// The networking layer's only dependency on the session system.
//
// Generic over Token so APIClient can be typed to the token shape it actually
// uses (e.g. BearerToken for Authorization header injection, CookieToken as a
// signal-only type, OpaqueSessionToken for custom header injection).

import Foundation

// MARK: - SessionTokenProviding

/// The session contract for the networking layer.
///
/// The networking layer should depend only on this protocol — it has no
/// knowledge of session state, credentials, or the concrete manager type.
/// `currentValidToken()` handles silent refresh transparently: if the token
/// is expired or close to expiry, it refreshes before returning.
///
/// Conforms to `@MainActor` — `currentValidToken()` is `async`, so callers
/// on any actor can `await` it and Swift hops to the main actor automatically.
///
/// ## Typical networking usage with 401-retry
///
/// ```swift
/// struct APIClient {
///     let tokens: any SessionTokenProviding<BearerToken>
///
///     func request(_ url: URL) async throws -> Data {
///         // 1. Get a valid token (auto-refreshes if expired or near expiry).
///         var req = try await authorized(URLRequest(url: url))
///         var (data, response) = try await URLSession.shared.data(for: req)
///
///         // 2. On 401, the locally valid token was rejected server-side
///         //    (revocation, rotation, clock skew). Force-refresh once and retry.
///         if (response as? HTTPURLResponse)?.statusCode == 401 {
///             try await tokens.forceRefreshToken()
///             req = try await authorized(URLRequest(url: url))
///             (data, response) = try await URLSession.shared.data(for: req)
///         }
///
///         guard (response as? HTTPURLResponse)?.statusCode != 401 else {
///             throw SessionError.sessionExpired
///         }
///         return data
///     }
///
///     private func authorized(_ req: URLRequest) async throws -> URLRequest {
///         let token = try await tokens.currentValidToken()
///         var req = req
///         req.setValue("Bearer \(token.accessToken)", forHTTPHeaderField: "Authorization")
///         return req
///     }
/// }
///
/// // Wiring — the APIClient never imports UserSessionManager
/// let client = APIClient(tokens: session)
/// ```
@MainActor
public protocol SessionTokenProviding<Token>: AnyObject, Sendable {
    /// The token shape this provider vends.
    associatedtype Token: AuthSessionToken

    /// Return a valid token, refreshing silently if necessary.
    ///
    /// - Throws: `SessionError.sessionNotFound` when no session is active.
    /// - Throws: `SessionError.sessionExpired` when the session has expired
    ///   and the credential store has been cleared (user must sign in again).
    /// - Throws: `SessionError.tokenRefreshFailed` when a required refresh fails.
    func currentValidToken() async throws -> Token

    /// Force an immediate token refresh, bypassing the expiry check.
    ///
    /// Call this when the server returns a `401` for a token that appears
    /// locally valid — for example due to server-side revocation, rolling
    /// token rotation, or clock skew. After a successful refresh, retry the
    /// request once. If the server returns a second `401`, the session is
    /// permanently invalid and `SessionError.sessionExpired` should be surfaced.
    ///
    /// If a refresh is already in flight (e.g. from the proactive timer or
    /// another `currentValidToken()` call), this method joins that task rather
    /// than starting a second one.
    ///
    /// - Throws: `SessionError.sessionNotFound` when no session is active.
    /// - Throws: `SessionError.sessionExpired` when the refresh is permanently
    ///   rejected (`invalidCredentials`) and the store has been cleared.
    /// - Throws: `SessionError.tokenRefreshFailed` on transient failures.
    func forceRefreshToken() async throws
}

// MARK: - AnyTokenProvider

/// A type-erased wrapper around `SessionTokenProviding` that exposes a single
/// raw string accessor for HTTP header injection.
///
/// Use `AnyTokenProvider` to decouple the networking layer entirely from the
/// token shape. The networking layer only calls `currentRawToken()` — it never
/// imports or references the concrete token type.
///
/// ```swift
/// struct APIClient {
///     let tokens: AnyTokenProvider
///
///     func request(_ url: URL) async throws -> Data {
///         var req = URLRequest(url: url)
///         if let value = try await tokens.currentRawToken() {
///             req.setValue("Bearer \(value)", forHTTPHeaderField: "Authorization")
///         }
///         return try await URLSession.shared.data(for: req).0
///     }
/// }
///
/// // BearerToken convenience — no closure needed
/// let client = APIClient(tokens: AnyTokenProvider(session))
/// ```
public final class AnyTokenProvider: Sendable {

    private let _rawValue: @Sendable () async throws -> String?

    /// Creates an `AnyTokenProvider` with a custom extraction closure.
    ///
    /// - Parameters:
    ///   - provider: The underlying `SessionTokenProviding` instance.
    ///   - rawValue: Closure that converts the token to an injectable string,
    ///     or returns `nil` when no header is required (e.g. cookie-based sessions).
    public init<P: SessionTokenProviding>(
        _ provider: P,
        rawValue: @escaping @Sendable (P.Token) -> String?
    ) {
        _rawValue = { [weak provider] in
            guard let provider else { throw SessionError.unknown("Provider deallocated") }
            let token = try await provider.currentValidToken()
            return rawValue(token)
        }
    }

    /// Returns the injectable header value for the current valid token,
    /// or `nil` for cookie-based sessions where no header is required.
    ///
    /// - Throws: `SessionError.sessionNotFound`, `.sessionExpired`, or
    ///   `.tokenRefreshFailed` when a valid token cannot be obtained.
    public func currentRawToken() async throws -> String? {
        try await _rawValue()
    }
}

// MARK: - Convenience AnyTokenProvider initialisers

public extension AnyTokenProvider {

    /// Creates an `AnyTokenProvider` for a `BearerToken` provider.
    /// Returns `accessToken` as the raw header value.
    convenience init<P: SessionTokenProviding>(_ provider: P) where P.Token == BearerToken {
        self.init(provider, rawValue: { $0.accessToken })
    }

    /// Creates an `AnyTokenProvider` for an `OpaqueSessionToken` provider.
    /// Returns `value` as the raw header value.
    convenience init<P: SessionTokenProviding>(_ provider: P) where P.Token == OpaqueSessionToken {
        self.init(provider, rawValue: { $0.value })
    }

    /// Creates an `AnyTokenProvider` for a `CookieToken` provider.
    /// Returns `nil` — cookies are handled automatically by `URLSession`.
    convenience init<P: SessionTokenProviding>(_ provider: P) where P.Token == CookieToken {
        self.init(provider, rawValue: { _ in nil })
    }
}
