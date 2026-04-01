// MARK: - Providers/MockIdentityProvider.swift
//
// For use in SwiftUI Previews and unit tests.
// Credential = EmailPasswordCredential
// Token      = BearerToken
//
// For tests that need a different token shape, define a parallel mock:
//   final class MockOpaqueProvider: IdentityProvider {
//       typealias Credential = EmailPasswordCredential
//       typealias Token      = OpaqueSessionToken
//       ...
//   }

import Foundation
@testable import SessionManager

public final class MockIdentityProvider: IdentityProvider, @unchecked Sendable {

    public typealias Credential = EmailPasswordCredential
    public typealias Token      = BearerToken

    public let providerID = "mock"

    public var simulatedLatency: Duration
    public var shouldFailSignIn: Bool
    public var shouldFailRefresh: Bool
    /// Error thrown when `shouldFailRefresh` is true.
    /// Defaults to `.invalidCredentials` (permanent — server rejected the token).
    /// Set to `.timeout` / `.providerError` / etc. to simulate a transient failure.
    public var refreshError: SessionError
    public var fixedUser: SessionUser
    public var tokenLifetime: TimeInterval

    public init(
        simulatedLatency: Duration    = .milliseconds(600),
        shouldFailSignIn: Bool        = false,
        shouldFailRefresh: Bool       = false,
        refreshError: SessionError    = .invalidCredentials,
        fixedUser: SessionUser        = SessionUser(
            id: "mock-001",
            displayName: "Jane Doe",
            email: "jane@example.com"
        ),
        tokenLifetime: TimeInterval   = 3600
    ) {
        self.simulatedLatency  = simulatedLatency
        self.shouldFailSignIn  = shouldFailSignIn
        self.shouldFailRefresh = shouldFailRefresh
        self.refreshError      = refreshError
        self.fixedUser         = fixedUser
        self.tokenLifetime     = tokenLifetime
    }

    public func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
        try await Task.sleep(for: simulatedLatency)
        guard !shouldFailSignIn else { throw SessionError.invalidCredentials }
        guard credential.email.contains("@"), credential.password.count >= 6 else {
            throw SessionError.invalidCredentials
        }
        return makeResult()
    }

    public func refreshToken(_ token: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> {
        try await Task.sleep(for: simulatedLatency)
        guard !shouldFailRefresh else { throw refreshError }
        return makeResult()
    }

    public func signOut(token: BearerToken) async throws {
        try await Task.sleep(for: .milliseconds(100))
    }

    public var nativeToken: BearerToken? = nil

    public func currentToken() async -> BearerToken? { nativeToken }

    private func makeResult() -> AuthResult<BearerToken> {
        AuthResult(
            user: fixedUser,
            token: BearerToken(
                accessToken:  "mock-access-\(UUID().uuidString)",
                refreshToken: "mock-refresh-\(UUID().uuidString)",
                expiresAt:    Date.now.addingTimeInterval(tokenLifetime)
            )
        )
    }
}

// MARK: - MockOpaqueProvider
//
// Demonstrates a username/password backend that returns an opaque session token —
// no OAuth2 involved, no refresh token, no scopes.

public final class MockOpaqueProvider: IdentityProvider, @unchecked Sendable {

    public typealias Credential = EmailPasswordCredential
    public typealias Token      = OpaqueSessionToken        // ← different token shape

    public let providerID = "mock-opaque"

    public var shouldFailSignIn: Bool

    public init(shouldFailSignIn: Bool = false) {
        self.shouldFailSignIn = shouldFailSignIn
    }

    public func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<OpaqueSessionToken> {
        guard !shouldFailSignIn else { throw SessionError.invalidCredentials }
        guard credential.email.contains("@"), credential.password.count >= 6 else {
            throw SessionError.invalidCredentials
        }
        return AuthResult(
            user:  SessionUser(id: "opaque-001", displayName: "Opaque User", email: credential.email),
            token: OpaqueSessionToken(value: "opaque-\(UUID().uuidString)",
                                      expiresAt: Date.now.addingTimeInterval(86400))
        )
    }

    // Opaque tokens have no refresh — a failed refresh means re-login
    public func refreshToken(_ token: OpaqueSessionToken, currentUser: SessionUser?) async throws -> AuthResult<OpaqueSessionToken> {
        throw SessionError.tokenRefreshFailed
    }

    public func signOut(token: OpaqueSessionToken) async throws {}
}
