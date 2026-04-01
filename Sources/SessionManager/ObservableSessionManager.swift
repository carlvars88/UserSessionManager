// MARK: - ObservableSessionManager.swift
//
// @Observable wrapper (iOS 17+ / macOS 14+).
// Use with @State / @Bindable / .environment().

#if canImport(Observation)
import Foundation
import Observation

/// A session manager that uses the `@Observable` macro for use with
/// `@State`, `@Bindable`, and `.environment()`.
///
/// Requires iOS 17+ / macOS 14+. For older deployment targets use
/// `UserSessionManager` (the `ObservableObject` variant) instead.
///
/// ## Setup
///
/// ```swift
/// typealias AppSession = ObservableSessionManager<MyProvider, KeychainCredentialStore<BearerToken>>
///
/// @main
/// struct MyApp: App {
///     @State private var session = AppSession(
///         provider: MyProvider(),
///         store:    KeychainCredentialStore()
///     )
///     var body: some Scene {
///         WindowGroup {
///             ContentView()
///                 .environment(session)
///         }
///     }
/// }
///
/// // In a view
/// @Environment(AppSession.self) private var session
/// ```
///
/// ## Networking layer
///
/// ```swift
/// let client = APIClient(tokens: AnyTokenProvider(session))
/// ```
@available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
@MainActor
@Observable
public final class ObservableSessionManager<
    Provider: IdentityProvider,
    Store: CredentialStore
>: UserSessionManaging, SessionTokenProviding
    where Store.Token == Provider.Token
{
    /// The current session state. Observed — SwiftUI views update automatically.
    public private(set) var state: SessionState = .loading(.restoringSession)

    /// The configuration supplied at initialisation.
    public let configuration: SessionManagerConfiguration

    @ObservationIgnored
    private let engine: SessionManagerEngine<Provider, Store>

    // MARK: Init

    /// Creates a session manager and immediately begins restoring any
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
        engine.onStateChange = { [weak self] newState in
            self?.state = newState
        }
    }

    deinit {
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
#endif
