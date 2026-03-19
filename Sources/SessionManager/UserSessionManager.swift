// MARK: - UserSessionManager.swift
//
// ObservableObject wrapper (iOS 14+ / macOS 11+)
//
// Use this when targeting iOS 14–16 or when you need @ObservedObject / @EnvironmentObject.
//
// Usage:
//   let session = UserSessionManager(provider: myProvider,
//                                    store: KeychainCredentialStore<BearerToken>())
//   RootView().environmentObject(session)
//   APIClient(tokens: AnyTokenProvider(session))

import Foundation
import Combine
import os.log

@MainActor
public final class UserSessionManager<
    Provider: IdentityProvider,
    Store: CredentialStore
>: ObservableObject, @preconcurrency UserSessionManaging, @preconcurrency SessionTokenProviding
    where Store.Token == Provider.Token
{
    @Published public private(set) var state: SessionState = .loading(.restoringSession)

    public let configuration: SessionManagerConfiguration

    private let engine: SessionManagerEngine<Provider, Store>

    // MARK: Init

    public init(
        provider: Provider,
        store: Store,
        configuration: SessionManagerConfiguration = SessionManagerConfiguration()
    ) {
        self.configuration = configuration
        self.engine = SessionManagerEngine(
            provider: provider,
            store: store,
            configuration: configuration
        )
        engine.onStateChange = { [weak self] newState in
            self?.state = newState
        }
    }

    // MARK: - Forwarding

    public func signIn(with credential: Provider.Credential) async {
        await engine.signIn(with: credential)
    }

    public func signOut() async {
        await engine.signOut()
    }

    public func reauthenticate(with credential: Provider.Credential) async throws {
        try await engine.reauthenticate(with: credential)
    }

    public func updateUser(_ user: SessionUser) {
        engine.updateUser(user)
    }

    public func currentValidToken() async throws -> Provider.Token {
        try await engine.currentValidToken()
    }

    public var currentUser:     SessionUser? { state.currentUser    }
    public var isAuthenticated: Bool         { state.isAuthenticated }
}
