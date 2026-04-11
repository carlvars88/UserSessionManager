// MARK: - UserSessionManaging.swift
//
// Product-facing session contract for the UI layer.
// Owns the state machine and all auth commands.
// Does not include token access — that belongs to SessionTokenProviding.
//
// Both protocols are @MainActor:
//   UserSessionManaging — state and updateUser are synchronous; they must run on
//     the main actor. Making the protocol @MainActor enforces this at compile time
//     and lets conforming classes drop @preconcurrency.
//   SessionTokenProviding — currentValidToken() is async, so callers can await it
//     from any context and Swift hops to the main actor transparently.
//   ObservableObject is an implementation detail — swap to @Observable freely.

import Foundation

// MARK: - UserSessionManaging

/// The session contract for the UI layer.
///
/// Conforms to `@MainActor` — all properties and methods must be accessed
/// on the main thread. SwiftUI views and `@ObservedObject` / `@State`
/// wrappers satisfy this automatically.
///
/// The networking layer should depend on `SessionTokenProviding` instead,
/// which exposes only `currentValidToken()` and carries no UI state.
///
/// ## Typical SwiftUI usage
///
/// ```swift
/// typealias AppSession = UserSessionManager<MyProvider, KeychainCredentialStore<BearerToken>>
///
/// @main
/// struct MyApp: App {
///     @StateObject private var session = AppSession(provider: MyProvider(),
///                                                   store: KeychainCredentialStore())
///     var body: some Scene {
///         WindowGroup {
///             ContentView()
///                 .environmentObject(session)
///                 .onAppear { session.restoreSession() }
///         }
///     }
/// }
/// ```
@MainActor
public protocol UserSessionManaging<Provider, Store>: Sendable
    where Provider: IdentityProvider,
          Store: CredentialStore,
          Store.Token == Provider.Token
{
    associatedtype Provider
    associatedtype Store

    /// The current session state. All derived properties (`isLoading`,
    /// `error`, `currentUser`, `isAuthenticated`) are computed from this
    /// single source of truth.
    var state: SessionState { get }

    /// Wires state propagation and begins restoring any previously persisted session.
    ///
    /// Call this once after the manager is created — typically in `onAppear` or
    /// the entry point of your app. All subsequent methods (`signIn`, `signOut`, etc.)
    /// await the restore before proceeding.
    func restoreSession()

    /// Begin a sign-in flow with the given credential.
    ///
    /// Transitions through `.loading(.signingIn)` and settles on
    /// `.signedIn` (success) or `.failed` (error). No-ops if an
    /// operation is already in progress.
    func signIn(with credential: Provider.Credential) async

    /// End the current session.
    ///
    /// Waits for any in-flight `signIn` or `reauthenticate` to finish,
    /// revokes the token via the provider, clears the credential store,
    /// and transitions to `.signedOut`.
    /// No-ops if the session is already in `.signedOut`.
    func signOut() async

    /// Verify the user's identity before a sensitive operation.
    ///
    /// Does not sign the user out on failure — the session remains
    /// `.signedIn` regardless of the outcome. Throws on error so the
    /// call site can react (e.g. show an error banner).
    func reauthenticate(with credential: Provider.Credential) async throws

    /// Update the local user profile without an identity-provider round-trip.
    ///
    /// Persists the new `SessionUser` to the credential store and
    /// transitions the state to `.signedIn(user)`. No-ops if no session
    /// is active.
    func updateUser(_ user: SessionUser)

    /// Fetch a fresh user profile from the identity provider and update the session.
    ///
    /// Calls `IdentityProvider.refreshToken(_:currentUser:)` with `currentUser: nil`,
    /// signalling the provider to re-fetch the user profile from its backend
    /// (e.g. the OpenID Connect UserInfo endpoint). The returned user and token
    /// are persisted and the state transitions to `.signedIn` with the fresh profile.
    ///
    /// Call this when you need up-to-date profile data — for example, after the
    /// user edits their display name or email on the server.
    ///
    /// - Throws: `SessionError.sessionNotFound` when no session is active.
    func refreshUser() async throws
}

// MARK: - SessionManagerConfiguration

/// Runtime configuration for `UserSessionManager` and `ObservableSessionManager`.
///
/// Pass a customised instance to the manager's initialiser. All properties
/// have sensible production defaults.
///
/// ```swift
/// let config = SessionManagerConfiguration(
///     proactiveRefreshBuffer: 120,   // refresh 2 min before expiry
///     operationTimeout:       15,    // fail fast on slow networks
///     logLevel:               .debug,
///     logger:                 PrintLogger()
/// )
/// let session = UserSessionManager(provider: …, store: …, configuration: config)
/// ```
public struct SessionManagerConfiguration: Sendable {

    /// Seconds before token expiry at which the engine triggers a proactive
    /// background refresh. Default: `60`.
    ///
    /// A higher value reduces the chance of a token expiring mid-request at
    /// the cost of more frequent refresh calls.
    public var proactiveRefreshBuffer: TimeInterval

    /// Maximum seconds to wait for a provider operation before throwing
    /// `SessionError.timeout`. Pass `nil` to wait indefinitely.
    /// Default: `30`.
    public var operationTimeout: TimeInterval?

    /// Minimum severity level emitted to the logger. Messages below this
    /// threshold are dropped before reaching the logger backend.
    /// Default: `.info`.
    public var logLevel: LogLevel

    /// The logging backend. Defaults to `OSLogger` (os.log), which writes
    /// to Console.app and the Xcode console. Inject `PrintLogger()` in
    /// tests or a custom conformer to forward to Datadog, Sentry, etc.
    public var logger: any SessionLogger

    public init(
        proactiveRefreshBuffer: TimeInterval = 60,
        operationTimeout: TimeInterval? = 30,
        logLevel: LogLevel = .info,
        logger: any SessionLogger = OSLogger()
    ) {
        self.proactiveRefreshBuffer = proactiveRefreshBuffer
        self.operationTimeout       = operationTimeout
        self.logLevel               = logLevel
        self.logger                 = logger
    }
}
