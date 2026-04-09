// MARK: - Models/SessionDomain.swift
//
// Pure domain types. No framework imports beyond Foundation. No IdP specifics.

import Foundation

// MARK: - SessionUser

/// A snapshot of the authenticated user's profile.
///
/// `SessionUser` is immutable. To update profile fields, call
/// `UserSessionManaging.updateUser(_:)` with a new instance.
public struct SessionUser: Sendable, Equatable, Codable, Identifiable {
    /// A stable, provider-issued identifier for the user (e.g. a UUID or `sub` claim).
    public let id: String
    /// A human-readable display name (full name, username, or email prefix).
    public let displayName: String
    /// The user's email address, if provided by the identity provider.
    public let email: String?
    /// URL to the user's avatar image, if provided by the identity provider.
    public let avatarURL: URL?
    /// Arbitrary key-value metadata from the identity provider.
    public let metadata: [String: String]

    public init(
        id: String,
        displayName: String,
        email: String? = nil,
        avatarURL: URL? = nil,
        metadata: [String: String] = [:]
    ) {
        self.id          = id
        self.displayName = displayName
        self.email       = email
        self.avatarURL   = avatarURL
        self.metadata    = metadata
    }

    /// Returns a copy of this user with the given key-value pairs merged into `metadata`.
    /// Existing keys are overwritten; keys not present in `additions` are preserved.
    public func adding(metadata additions: [String: String]) -> SessionUser {
        var merged = metadata
        merged.merge(additions) { _, new in new }
        return SessionUser(id: id, displayName: displayName, email: email,
                           avatarURL: avatarURL, metadata: merged)
    }

    /// Returns a copy of this user with the specified metadata keys removed.
    public func removing(metadataKeys keys: Set<String>) -> SessionUser {
        var updated = metadata
        keys.forEach { updated.removeValue(forKey: $0) }
        return SessionUser(id: id, displayName: displayName, email: email,
                           avatarURL: avatarURL, metadata: updated)
    }

    // Custom decoder so sessions stored before `metadata` was added decode cleanly.
    public init(from decoder: Decoder) throws {
        let c           = try decoder.container(keyedBy: CodingKeys.self)
        id          = try c.decode(String.self, forKey: .id)
        displayName = try c.decode(String.self, forKey: .displayName)
        email       = try c.decodeIfPresent(String.self, forKey: .email)
        avatarURL   = try c.decodeIfPresent(URL.self,    forKey: .avatarURL)
        metadata    = (try? c.decodeIfPresent([String: String].self, forKey: .metadata)) ?? [:]
    }
}

// MARK: - AuthSessionToken

/// The behavioural contract every token type must satisfy.
///
/// Deliberately minimal — carries only what the session manager needs to
/// make decisions. All other fields (scopes, token type, raw values…) are
/// the concrete type's business.
///
/// ## Implementing a custom token type
///
/// ```swift
/// struct MyToken: AuthSessionToken {
///     let value: String
///     let expiresAt: Date?
///     var isExpired: Bool {
///         expiresAt.map { $0 <= Date() } ?? false
///     }
/// }
/// ```
public protocol AuthSessionToken: Sendable, Codable, Equatable {

    /// `true` when the token can no longer be used and a refresh is required.
    var isExpired: Bool { get }

    /// Expiration date, if known. The session manager uses this to schedule
    /// proactive refresh timers. Return `nil` for tokens that never expire.
    var expiresAt: Date? { get }
}

public extension AuthSessionToken {
    /// Default implementation returns `nil` (token does not expire).
    var expiresAt: Date? { nil }
}

// MARK: - BearerToken

/// An OAuth2 / Bearer token pair.
///
/// Use with providers that return access and refresh tokens — Google,
/// Auth0, Okta, Keycloak, Azure AD, or any RFC 6749-compliant server.
public struct BearerToken: AuthSessionToken {
    /// The short-lived access token sent in `Authorization: Bearer` headers.
    public let accessToken: String
    /// The long-lived refresh token used to obtain a new access token.
    /// `nil` for providers that do not issue refresh tokens.
    public let refreshToken: String?
    /// When the access token expires. `nil` if the provider does not return `expires_in`.
    public let expiresAt: Date?
    /// The token type (typically `"Bearer"`).
    public let tokenType: String
    /// OAuth2 scopes granted for this token.
    public let scopes: [String]

    /// `true` when `expiresAt` is in the past.
    public var isExpired: Bool {
        guard let exp = expiresAt else { return false }
        return exp <= Date()
    }

    public init(
        accessToken: String,
        refreshToken: String? = nil,
        expiresAt: Date? = nil,
        tokenType: String = "Bearer",
        scopes: [String] = []
    ) {
        self.accessToken  = accessToken
        self.refreshToken = refreshToken
        self.expiresAt    = expiresAt
        self.tokenType    = tokenType
        self.scopes       = scopes
    }
}

// MARK: - OpaqueSessionToken

/// A single opaque session token returned by a custom auth backend.
///
/// Has no refresh token — when the token expires the session manager
/// transitions to `.expired` and the user must sign in again.
public struct OpaqueSessionToken: AuthSessionToken {
    /// The opaque token string issued by the server.
    public let value: String
    /// When the token expires, if known.
    public let expiresAt: Date?

    /// `true` when `expiresAt` is in the past.
    public var isExpired: Bool {
        guard let exp = expiresAt else { return false }
        return exp <= Date()
    }

    public init(value: String, expiresAt: Date? = nil) {
        self.value     = value
        self.expiresAt = expiresAt
    }
}

// MARK: - CookieToken

/// A presence signal for cookie-based sessions.
///
/// No token data is held in-process — the actual cookie lives in
/// `HTTPCookieStorage` and is attached to requests automatically by
/// `URLSession`. The session manager uses this type as a signal only:
/// if a `CookieToken` exists in the credential store, the session is
/// assumed valid.
public struct CookieToken: AuthSessionToken {
    /// The name of the cookie that identifies the session (e.g. `"session_id"`).
    public let cookieName: String
    /// When the cookie expires, if known.
    public let expiresAt: Date?

    /// `true` when `expiresAt` is in the past.
    public var isExpired: Bool {
        guard let exp = expiresAt else { return false }
        return exp <= Date()
    }

    public init(cookieName: String, expiresAt: Date? = nil) {
        self.cookieName = cookieName
        self.expiresAt  = expiresAt
    }
}

// MARK: - AuthOperation

/// An in-progress session operation. Associated with the `.loading` state.
public enum AuthOperation: Equatable, Sendable {
    /// The session manager is restoring a previously persisted session on launch.
    case restoringSession
    /// A sign-in operation is in progress.
    case signingIn
    /// A sign-out operation is in progress.
    case signingOut
    /// A background token refresh is in progress.
    case refreshingToken
    /// A re-authentication operation is in progress.
    case reauthenticating
}

// MARK: - SessionState

/// The complete state of the session lifecycle.
///
/// `SessionState` is the single source of truth. All derived properties
/// (`isLoading`, `error`, `currentUser`, `isAuthenticated`) are computed
/// from it — they cannot contradict the state.
///
/// ## State machine
/// ```
/// .loading(.restoringSession)  ← initial state on every app launch
///         ↓
/// .signedOut  ←──────────────────────────────────────────┐
///         ↓                                              │
/// .loading(.signingIn)                             .signOut()
///         ↓                                              │
/// .signedIn(SessionUser) ────────────────────────────────┘
///         ↓ (token refresh rejected by server)
/// .expired
///         ↓ (any auth error)
/// .failed(SessionError)
/// ```
public enum SessionState: Equatable, Sendable {

    /// The session manager is performing an async operation.
    case loading(AuthOperation)

    /// No session exists. The user must sign in.
    case signedOut

    /// A valid session exists for the given user.
    case signedIn(SessionUser)

    /// The most recent auth operation failed.
    case failed(SessionError)

    /// The server permanently rejected a token refresh. The token has been
    /// cleared but the user profile is preserved — the user must sign in again
    /// but their identity is still known (display name, email, metadata).
    case expired(SessionUser)

    // MARK: Derived helpers

    /// `true` while any auth operation is in progress.
    public var isLoading: Bool {
        if case .loading = self { return true }
        return false
    }

    /// The error from the most recent failed operation, or `nil`.
    public var error: SessionError? {
        if case .failed(let e) = self { return e }
        return nil
    }

    /// The signed-in user, or `nil` when not authenticated.
    ///
    /// Returns the user in both `.signedIn` and `.expired` states —
    /// token expiry does not erase the user's identity.
    public var currentUser: SessionUser? {
        switch self {
        case .signedIn(let u), .expired(let u): return u
        default: return nil
        }
    }

    /// `true` only in the `.signedIn` state.
    public var isAuthenticated: Bool {
        if case .signedIn = self { return true }
        return false
    }

    /// `true` only in the `.expired` state.
    public var isExpired: Bool {
        if case .expired = self { return true }
        return false
    }
}

// MARK: - SessionError

/// Errors produced by the session manager and its identity providers.
public enum SessionError: Error, LocalizedError, Equatable, Sendable {

    /// The supplied credentials were rejected by the server.
    /// During token refresh this is treated as a **permanent** failure —
    /// the credential store is cleared and the session transitions to `.expired`.
    case invalidCredentials

    /// The identity provider returned an error with the given description.
    case providerError(String)

    /// A token refresh attempt failed. May be transient (network, timeout)
    /// or permanent (`invalidCredentials` from the server).
    case tokenRefreshFailed

    /// The session has expired and the credential store has been cleared.
    /// The user must sign in again.
    case sessionExpired

    /// No active session was found. Thrown by `currentValidToken()` when
    /// the session is in any non-authenticated state other than `.expired`.
    case sessionNotFound

    /// A keychain read or write operation failed with the given reason.
    case credentialStoreFailed(String)

    /// The operation was cancelled by the user (e.g. the user dismissed
    /// an `ASWebAuthenticationSession` prompt).
    case cancelled

    /// The operation did not complete within `SessionManagerConfiguration.operationTimeout`.
    case timeout

    /// An unexpected error occurred. The associated string is the underlying
    /// error's `localizedDescription`.
    case unknown(String)

    public var errorDescription: String? {
        switch self {
        case .invalidCredentials:           return "Invalid credentials. Please try again."
        case .providerError(let msg):       return msg
        case .tokenRefreshFailed:           return "Could not refresh your session."
        case .sessionExpired:               return "Your session has expired. Please sign in again."
        case .sessionNotFound:              return "No active session found."
        case .credentialStoreFailed(let r): return "Secure storage error: \(r)"
        case .cancelled:                    return "Sign-in was cancelled."
        case .timeout:                      return "The operation timed out. Please try again."
        case .unknown(let msg):             return "Unexpected error: \(msg)"
        }
    }
}
