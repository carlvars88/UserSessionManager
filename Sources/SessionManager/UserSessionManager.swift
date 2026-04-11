// MARK: - UserSessionManager.swift
//
// ObservableObject wrapper (iOS 16+ / macOS 12+).
// Use with @StateObject / @ObservedObject / @EnvironmentObject.

import Foundation
import Combine

/// A session manager that conforms to `ObservableObject` for use with
/// `@StateObject`, `@ObservedObject`, and `@EnvironmentObject`.
///
/// Compatible with iOS 16+ and macOS 12+. For iOS 17+ / macOS 14+, consider
/// `ObservableSessionManager` which uses the `@Observable` macro instead.
///
/// ## Setup
///
/// Define a `typealias` at the app level to avoid repeating the generic parameters:
///
/// ```swift
/// typealias AppSession = UserSessionManager<MyProvider, KeychainCredentialStore<BearerToken>>
///
/// @main
/// struct MyApp: App {
///     @StateObject private var session = AppSession(
///         provider: MyProvider(),
///         store:    KeychainCredentialStore()
///     )
///     var body: some Scene {
///         WindowGroup {
///             ContentView()
///                 .environmentObject(session)
///         }
///     }
/// }
/// ```
///
/// ## Networking layer
///
/// Pass the manager as `AnyTokenProvider` so the networking layer has no
/// dependency on the session type:
///
/// ```swift
/// let client = APIClient(tokens: AnyTokenProvider(session))
/// ```
@MainActor
public final class UserSessionManager<
    Provider: IdentityProvider,
    Store: CredentialStore
>: ObservableObject, UserSessionManaging, SessionTokenProviding
    where Store.Token == Provider.Token
{
    /// The current session state. Published — SwiftUI views update automatically.
    @Published public private(set) var state: SessionState = .loading(.restoringSession)

    /// The configuration supplied at initialisation.
    public let configuration: SessionManagerConfiguration

    private let engine: SessionManagerEngine<Provider, Store>

    // MARK: Init

    /// Creates a session manager.
    ///
    /// Call ``restoreSession()`` after initialization to begin restoring any
    /// previously persisted session.
    ///
    /// - Parameters:
    ///   - provider: The identity provider that handles sign-in, refresh, and sign-out.
    ///   - store: The credential store used to persist the token between launches.
    ///   - configuration: Runtime configuration. Defaults to production-safe values.
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
    }

    /// Wires state propagation and begins restoring any previously persisted session.
    ///
    /// Call this once after the manager is created — typically in `onAppear` or
    /// the entry point of your app. All public methods (`signIn`, `signOut`, etc.)
    /// await the restore before proceeding, so it is safe to call them immediately
    /// after this method returns without waiting for the state to leave `.loading`.
    public func restoreSession() {
        engine.onStateChange = { [weak self] newState in self?.state = newState }
        engine.start()
    }

    deinit {
        // tearDown() is @MainActor — hop via a fire-and-forget Task.
        // The Task captures engine strongly, keeping it alive until tearDown runs.
        let engine = engine
        Task { await engine.tearDown() }
    }

    // MARK: - UserSessionManaging

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

    public func refreshUser() async throws {
        try await engine.refreshUser()
    }

    // MARK: - SessionTokenProviding

    public func currentValidToken() async throws -> Provider.Token {
        try await engine.currentValidToken()
    }

    public func forceRefreshToken() async throws {
        try await engine.forceRefreshToken()
    }

    // MARK: - Convenience

    /// The signed-in user, or `nil` when not authenticated.
    public var currentUser: SessionUser? { state.currentUser }

    /// `true` only in the `.signedIn` state.
    public var isAuthenticated: Bool { state.isAuthenticated }
}
