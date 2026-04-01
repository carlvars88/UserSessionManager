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

import Foundation

// MARK: - AuthResult

/// The output of every successful `IdentityProvider` operation.
///
/// Bundles the authenticated user and the token issued for that session.
/// Generic over the provider's own `Token` type.
public struct AuthResult<Token: AuthSessionToken>: Sendable {
    /// The authenticated user's profile.
    public let user: SessionUser
    /// The session token to cache and present to the networking layer.
    public let token: Token

    public init(user: SessionUser, token: Token) {
        self.user  = user
        self.token = token
    }
}

// MARK: - IdentityProvider

/// The contract between the session manager and your authentication backend.
///
/// Implement `IdentityProvider` once per backend. The two associated types
/// bind the provider to a specific credential input shape and token output
/// shape at compile time:
///
/// ```swift
/// final class MyProvider: IdentityProvider, Sendable {
///     typealias Credential = EmailPasswordCredential
///     typealias Token      = BearerToken
///
///     let providerID = "my-backend"
///
///     func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<BearerToken> { … }
///     func refreshToken(_ token: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> { … }
///     func signOut(token: BearerToken) async throws { … }
/// }
/// ```
///
/// `reauthenticate(user:with:)` and `currentToken()` have default
/// implementations and are optional to override.
public protocol IdentityProvider: Sendable {

    /// The credential shape this provider accepts. Enforced at compile time.
    associatedtype Credential: AuthCredential

    /// The token shape this provider produces. Must match `CredentialStore.Token`.
    associatedtype Token: AuthSessionToken

    /// A stable, human-readable identifier used in log messages (e.g. `"firebase"`, `"oauth2"`).
    var providerID: String { get }

    /// Exchange a credential for a session token.
    ///
    /// Called by the session manager during `signIn(with:)`. Throw
    /// `SessionError.invalidCredentials` when the server rejects the credential.
    func signIn(with credential: Credential) async throws -> AuthResult<Token>

    /// Exchange an existing token for a fresh one.
    ///
    /// Called automatically by the session manager when a token is expired or
    /// close to expiry. `currentUser` is the user already held by the engine;
    /// return it directly to avoid an extra network round-trip. Pass it through
    /// unchanged unless the provider needs to re-fetch the user profile.
    ///
    /// When `currentUser` is `nil` (session restore with no cached user), fetch
    /// the user from your backend and include it in the returned `AuthResult`.
    ///
    /// - Parameters:
    ///   - token: The current (possibly expired) token.
    ///   - currentUser: The cached user, or `nil` if no user is available.
    func refreshToken(_ token: Token, currentUser: SessionUser?) async throws -> AuthResult<Token>

    /// Revoke the token and terminate the server-side session.
    ///
    /// Called during `signOut()`. Errors are logged but do not prevent the
    /// local session from being cleared.
    func signOut(token: Token) async throws

    /// Re-authenticate an already signed-in user before a sensitive operation.
    ///
    /// The default implementation delegates to `signIn(with:)`. Override when
    /// your backend offers a dedicated re-authentication endpoint.
    ///
    /// The session manager guarantees the state returns to `.signedIn` on both
    /// success and failure — a failed re-authentication does not sign the user out.
    func reauthenticate(user: SessionUser, with credential: Credential) async throws -> AuthResult<Token>

    /// Return a provider-cached token if one is already available in-process.
    ///
    /// Override when the identity SDK maintains its own token cache (e.g. the
    /// Firebase Auth SDK). Return `nil` (the default) to let `CredentialStore`
    /// drive session restore.
    func currentToken() async -> Token?
}

// MARK: - Default Implementations

public extension IdentityProvider {

    /// Default: returns `nil`. Override to expose a provider-managed token cache.
    func currentToken() async -> Token? { nil }

    /// Default: delegates to `signIn(with:)`.
    func reauthenticate(
        user: SessionUser,
        with credential: Credential
    ) async throws -> AuthResult<Token> {
        try await signIn(with: credential)
    }
}
