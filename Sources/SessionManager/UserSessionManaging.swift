// MARK: - UserSessionManaging.swift
//
// Product-facing session contract for the UI layer.
// Owns the state machine and all auth commands.
// Does not include token access — that belongs to SessionTokenProviding.
//
// Neither protocol carries @MainActor or ObservableObject:
//   @MainActor       is an implementation detail of the concrete class
//   ObservableObject is an implementation detail — swap to @Observable freely

import Foundation

// MARK: - UserSessionManaging

public protocol UserSessionManaging<Provider, Store>: Sendable
    where Provider: IdentityProvider,
          Store: CredentialStore,
          Store.Token == Provider.Token
{
    associatedtype Provider
    associatedtype Store

    /// Single source of truth. isLoading, error, currentUser all derived from here.
    var state: SessionState { get }

    /// Only Provider.Credential is accepted — compile-time enforced.
    func signIn(with credential: Provider.Credential) async

    func signOut() async

    /// Re-authenticate before a sensitive operation.
    func reauthenticate(with credential: Provider.Credential) async throws

    /// Local profile update — no IdP round-trip.
    func updateUser(_ user: SessionUser)
}

// MARK: - SessionManagerConfiguration

public struct SessionManagerConfiguration: Sendable {

    /// Seconds before token expiry to trigger a proactive refresh.
    public var proactiveRefreshBuffer: TimeInterval

    /// Maximum time (in seconds) to wait for a provider operation before throwing `.timeout`.
    /// Pass `nil` to wait indefinitely (not recommended for production).
    public var operationTimeout: TimeInterval?

    public init(
        proactiveRefreshBuffer: TimeInterval = 60,
        operationTimeout: TimeInterval? = 30
    ) {
        self.proactiveRefreshBuffer = proactiveRefreshBuffer
        self.operationTimeout       = operationTimeout
    }
}
