// MARK: - Protocols/IdentityProvider.swift
//
// TWO associatedtypes — both enforced at compile time:
//
//   associatedtype Credential: AuthCredential   — what goes *in*  (sign-in input)
//   associatedtype Token: AuthSessionToken      — what comes *out* (session material)
//
// Each provider declares exactly which credential it accepts AND which token
// shape it produces. Mismatches between provider and store are caught at the
// UserSessionManager<Provider, Store> where clause:
//
//   where Store.Token == Provider.Token   ← build error if they disagree
//
// Examples:
//
//   final class EmailPasswordProvider: IdentityProvider {
//       typealias Credential = EmailPasswordCredential
//       typealias Token      = OpaqueSessionToken      // custom backend
//   }
//
//   final class GoogleOAuthProvider: IdentityProvider {
//       typealias Credential = OAuthCredential
//       typealias Token      = BearerToken             // OAuth2
//   }
//
//   final class AppleProvider: IdentityProvider {
//       typealias Credential = AppleCredential
//       typealias Token      = BearerToken             // JWT from Apple
//   }
//
//   final class CookieAuthProvider: IdentityProvider {
//       typealias Credential = EmailPasswordCredential
//       typealias Token      = CookieToken             // no token in process
//   }

import Foundation

// MARK: - AuthResult

/// The output of every successful IdentityProvider operation.
/// Generic over the provider's own Token type.
public struct AuthResult<Token: AuthSessionToken>: Sendable {
    public let user: SessionUser
    public let token: Token

    public init(user: SessionUser, token: Token) {
        self.user  = user
        self.token = token
    }
}

// MARK: - IdentityProvider

public protocol IdentityProvider: Sendable {

    /// The credential shape this provider accepts. Compile-time enforced.
    associatedtype Credential: AuthCredential

    /// The token shape this provider produces. Compile-time enforced.
    /// Must match the Token type of the paired CredentialStore.
    associatedtype Token: AuthSessionToken

    var providerID: String { get }

    /// Sign in. Only `Credential` is accepted — wrong type is a build error.
    func signIn(with credential: Credential) async throws -> AuthResult<Token>

    /// Silently exchange an existing token for a fresh one.
    func refreshToken(_ token: Token) async throws -> AuthResult<Token>

    /// Revoke the token / clear server-side session.
    func signOut(token: Token) async throws

    /// Re-authenticate an already signed-in user before a sensitive operation.
    func reauthenticate(user: SessionUser, with credential: Credential) async throws -> AuthResult<Token>

    /// Return a provider-cached token if available (e.g. Firebase SDK's own store).
    /// Return nil to let CredentialStore drive session restore.
    func currentToken() async -> Token?
}

// MARK: - Default Implementations

public extension IdentityProvider {

    func currentToken() async -> Token? { nil }

    func reauthenticate(
        user: SessionUser,
        with credential: Credential
    ) async throws -> AuthResult<Token> {
        try await signIn(with: credential)
    }
}
