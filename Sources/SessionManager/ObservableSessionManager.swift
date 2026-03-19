// MARK: - ObservableSessionManager.swift
//
// @Observable wrapper (iOS 17+ / macOS 14+)
//
// Use this when targeting iOS 17+ and you want the modern Observation framework.
// Works with SwiftUI's @State, @Bindable, and automatic view invalidation
// without @ObservedObject or @EnvironmentObject.
//
// Usage:
//   @State private var session = ObservableSessionManager(
//       provider: MyProvider(), store: KeychainCredentialStore<BearerToken>()
//   )
//   ContentView().environment(session)

#if canImport(Observation)
import Foundation
import Observation

@available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
@MainActor
@Observable
public final class ObservableSessionManager<
    Provider: IdentityProvider,
    Store: CredentialStore
>: @preconcurrency UserSessionManaging, @preconcurrency SessionTokenProviding
    where Store.Token == Provider.Token
{
    public private(set) var state: SessionState = .loading(.restoringSession)

    public let configuration: SessionManagerConfiguration

    @ObservationIgnored
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
#endif
