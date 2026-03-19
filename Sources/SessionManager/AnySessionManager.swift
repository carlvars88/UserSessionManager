// MARK: - AnySessionManager.swift
//
// Type eraser — hides both Provider and Store generics from views and APIClient.
//
// Conforms to SessionTokenProviding<Token> so it can be injected into APIClient
// with the same interface as the concrete manager.
//
// Usage (ObservableObject):
//   let manager = UserSessionManager(provider: GoogleOAuthProvider(),
//                                    store:    KeychainCredentialStore<BearerToken>())
//   let erased  = AnySessionManager(manager)
//   RootView().environmentObject(erased)
//
// Usage (Observable, iOS 17+):
//   let manager = ObservableSessionManager(provider: GoogleOAuthProvider(),
//                                          store:    KeychainCredentialStore<BearerToken>())
//   let erased  = AnySessionManager(manager)

import Foundation
import Combine

@MainActor
public final class AnySessionManager<Credential: AuthCredential, Token: AuthSessionToken>:
    ObservableObject, SessionTokenProviding
{
    @Published public private(set) var state: SessionState

    private let _signIn:            (Credential) async -> Void
    private let _signOut:           () async -> Void
    private let _reauthenticate:    (Credential) async throws -> Void
    private let _updateUser:        (SessionUser) -> Void
    private let _currentValidToken: () async throws -> Token
    private var cancellables:       Set<AnyCancellable> = []

    // MARK: Init — from UserSessionManager (ObservableObject)

    public init<P: IdentityProvider, S: CredentialStore>(
        _ manager: UserSessionManager<P, S>
    ) where P.Credential == Credential, P.Token == Token, S.Token == Token {

        state = manager.state

        _signIn            = { [weak manager] in await manager?.signIn(with: $0) }
        _signOut           = { [weak manager] in await manager?.signOut() }
        _reauthenticate    = { [weak manager] in try await manager?.reauthenticate(with: $0) }
        _updateUser        = { [weak manager] in manager?.updateUser($0) }
        _currentValidToken = { [weak manager] in
            guard let m = manager else { throw SessionError.unknown("Manager deallocated") }
            return try await m.currentValidToken()
        }

        manager.$state
            .receive(on: RunLoop.main)
            .assign(to: \.state, on: self)
            .store(in: &cancellables)
    }

    // MARK: Init — from ObservableSessionManager (@Observable, iOS 17+)

    #if canImport(Observation)
    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    public init<P: IdentityProvider, S: CredentialStore>(
        _ manager: ObservableSessionManager<P, S>
    ) where P.Credential == Credential, P.Token == Token, S.Token == Token {

        state = manager.state

        _signIn            = { [weak manager] in await manager?.signIn(with: $0) }
        _signOut           = { [weak manager] in await manager?.signOut() }
        _reauthenticate    = { [weak manager] in try await manager?.reauthenticate(with: $0) }
        _updateUser        = { [weak manager] in manager?.updateUser($0) }
        _currentValidToken = { [weak manager] in
            guard let m = manager else { throw SessionError.unknown("Manager deallocated") }
            return try await m.currentValidToken()
        }

        // Bridge @Observable state changes to @Published via withObservationTracking
        Task { @MainActor [weak self, weak manager] in
            while let self, let manager {
                self.state = manager.state
                await withCheckedContinuation { continuation in
                    withObservationTracking {
                        _ = manager.state
                    } onChange: {
                        continuation.resume()
                    }
                }
            }
        }
    }
    #endif

    // MARK: - Forwarding

    public func signIn(with credential: Credential) async    { await _signIn(credential) }
    public func signOut()                           async    { await _signOut() }
    public func reauthenticate(with c: Credential)  async throws { try await _reauthenticate(c) }
    public func updateUser(_ user: SessionUser)               { _updateUser(user) }
    public func currentValidToken()                 async throws -> Token { try await _currentValidToken() }

    public var currentUser:     SessionUser? { state.currentUser    }
    public var isAuthenticated: Bool         { state.isAuthenticated }
}
