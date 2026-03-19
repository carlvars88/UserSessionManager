// MARK: - Models/SessionDomain.swift
//
// Pure domain types. No framework imports beyond Foundation. No IdP specifics.
//
// KEY CHANGE — AuthSessionToken protocol
// ───────────────────────────────────────
// The old concrete `AuthToken` struct assumed every backend speaks OAuth2/Bearer.
// `AuthSessionToken` is the abstraction every generic is now parameterised over.
// Each IdentityProvider declares its own concrete Token type that conforms to it.
//
// Three concrete token types are provided out of the box:
//   BearerToken        — OAuth2 / JWT (access + refresh + expiry + scopes)
//   OpaqueSessionToken — custom backend (single opaque string, optional expiry)
//   CookieToken        — cookie-based session (no data carried in-process)
//
// Adding a new token shape requires zero changes to the session manager or protocols.

import Foundation

// MARK: - SessionUser

public struct SessionUser: Sendable, Equatable, Codable, Identifiable {
    public let id: String
    public let displayName: String
    public let email: String?
    public let avatarURL: URL?
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
}

// MARK: - AuthSessionToken

/// The behavioural contract every token type must satisfy.
///
/// Deliberately minimal — carries only what the session manager needs to make
/// decisions. All other fields (scopes, token type, raw values…) are the
/// concrete type's business.
public protocol AuthSessionToken: Sendable, Codable, Equatable {

    /// True when the token can no longer be used and a refresh is required.
    var isExpired: Bool { get }

    /// True when the token is close enough to expiry that a proactive refresh
    /// should be triggered (default: within 60 seconds).
    var needsProactiveRefresh: Bool { get }

    /// Expiration date, if applicable. Used by the session manager to schedule
    /// proactive refresh timers. Return nil for tokens that never expire.
    var expiresAt: Date? { get }
}

// Default implementation — conformers can override with their own threshold.
public extension AuthSessionToken {
    var needsProactiveRefresh: Bool { isExpired }
    var expiresAt: Date? { nil }
}

// MARK: - BearerToken  (OAuth2 / JWT)

/// OAuth2 / Bearer token pair.
/// Use with providers that return access + refresh tokens (Google, Firebase,
/// Auth0, custom OAuth2 servers, etc.).
public struct BearerToken: AuthSessionToken {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresAt: Date?
    public let tokenType: String
    public let scopes: [String]

    public var isExpired: Bool {
        guard let exp = expiresAt else { return false }
        return exp <= Date()
    }

    public var needsProactiveRefresh: Bool {
        guard let exp = expiresAt else { return false }
        return exp.timeIntervalSinceNow < 60
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

// MARK: - OpaqueSessionToken  (custom / username-password backends)

/// A single opaque session token returned by a custom auth backend.
/// Has no refresh token — expiry (if any) causes a full re-login.
public struct OpaqueSessionToken: AuthSessionToken {
    public let value: String
    public let expiresAt: Date?

    public var isExpired: Bool {
        guard let exp = expiresAt else { return false }
        return exp <= Date()
    }

    public var needsProactiveRefresh: Bool {
        guard let exp = expiresAt else { return false }
        return exp.timeIntervalSinceNow < 60
    }

    public init(value: String, expiresAt: Date? = nil) {
        self.value     = value
        self.expiresAt = expiresAt
    }
}

// MARK: - CookieToken  (cookie-based sessions)

/// Represents a session maintained entirely via HTTP cookies.
/// No token data is held in-process — the cookie lives in HTTPCookieStorage.
/// The manager uses this as a presence signal only: if it exists, the session
/// is assumed valid; if refresh is needed the provider must re-validate.
public struct CookieToken: AuthSessionToken {
    /// The cookie name that identifies the session (e.g. "session_id").
    public let cookieName: String
    public let expiresAt: Date?

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

public enum AuthOperation: Equatable, Sendable {
    case restoringSession
    case signingIn
    case signingOut
    case refreshingToken
    case reauthenticating
}

// MARK: - SessionState
//
// Single source of truth for the entire session lifecycle.
// isLoading and lastError are derived from state — they cannot contradict it.

public enum SessionState: Equatable, Sendable {

    /// App launch — restoring a persisted session.
    case loading(AuthOperation)

    /// No session. Ready to sign in.
    case signedOut

    /// A valid session exists.
    case signedIn(SessionUser)

    /// The last auth operation failed.
    case failed(SessionError)

    /// A session existed but silent token refresh failed.
    case expired

    // MARK: Derived helpers

    public var isLoading: Bool {
        if case .loading = self { return true }
        return false
    }

    public var error: SessionError? {
        if case .failed(let e) = self { return e }
        return nil
    }

    public var currentUser: SessionUser? {
        if case .signedIn(let u) = self { return u }
        return nil
    }

    public var isAuthenticated: Bool {
        if case .signedIn = self { return true }
        return false
    }
}

// MARK: - SessionError

public enum SessionError: Error, LocalizedError, Equatable, Sendable {
    case invalidCredentials
    case providerError(String)
    case tokenRefreshFailed
    case sessionExpired
    case sessionNotFound
    case credentialStoreFailed(String)
    case cancelled
    case timeout
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
