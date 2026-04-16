// MARK: - SessionManagerEngine.swift
//
// Internal engine that owns all session management business logic.
// No observation framework dependency — UserSessionManager (ObservableObject)
// and ObservableSessionManager (@Observable) are thin wrappers over this engine.

import Foundation

@MainActor
internal final class SessionManagerEngine<
    Provider: IdentityProvider,
    Store: CredentialStore
> where Store.Token == Provider.Token {

    // ── State ───────────────────────────────────────────────────────────────
    internal private(set) var state: SessionState = .loading(.restoringSession) {
        didSet { onStateChange?(state) }
    }

    /// Called on every state transition. Wrappers use this to sync their published state.
    var onStateChange: (@MainActor (SessionState) -> Void)?

    // ── Injected dependencies ───────────────────────────────────────────────
    let provider: Provider
    let store:    Store
    let configuration: SessionManagerConfiguration

    // ── In-process token cache ──────────────────────────────────────────────
    private var cachedToken: Provider.Token?

    // ── One-flight refresh guard ────────────────────────────────────────────
    // Void return: callers never read the token from the task — they read cachedToken
    // after it settles. Task<Void,Error> is used (not Never) so concurrent callers of
    // currentValidToken() receive the thrown error if refresh fails.
    private var ongoingRefreshTask: Task<Void, Error>?

    // ── Current user-initiated operation (signIn, reauthenticate) ────────────
    // signOut awaits this before proceeding, ensuring it always wins.
    private var currentOperationTask: Task<Void, Never>?

    // ── Session restore gate ──────────────────────────────────────────────
    private var restoreTask: Task<Void, Never>?

    // ── Pending user-update persistence ─────────────────────────────────────
    private var pendingPersistTask: Task<Void, Never>?

    // ── Proactive expiry timer ──────────────────────────────────────────────
    // The only task that requires explicit cancellation: it sleeps for up to
    // (tokenLifetime - proactiveRefreshBuffer) seconds. All other tasks either
    // nil themselves on completion or exit promptly via [weak self] checks.
    private var refreshTimer: Task<Void, Never>?

    // ── Logger ──────────────────────────────────────────────────────────────
    private let log:      any SessionLogger
    private let logLevel: LogLevel

    // MARK: Init

    init(
        provider: Provider,
        store: Store,
        configuration: SessionManagerConfiguration = SessionManagerConfiguration()
    ) {
        self.provider      = provider
        self.store         = store
        self.configuration = configuration
        self.log           = configuration.logger
        self.logLevel      = configuration.logLevel
    }

    /// Begins the initial session restore. Must be called once after init, typically
    /// by the wrapper's init (`UserSessionManager`, `ObservableSessionManager`).
    func start() {
        guard restoreTask == nil else { return }
        restoreTask = Task { await self.restoreSession() }
    }

    /// Applies the configured `logLevel` threshold then delegates to the injected logger.
    /// Use this instead of calling `log` directly so the threshold is always respected.
    private func emit(
        _ level: LogLevel,
        _ message: @autoclosure @Sendable () -> String,
        file: String = #fileID, function: String = #function, line: UInt = #line
    ) {
        guard level >= logLevel, log.isEnabled(level) else { return }
        log.log(level: level, message(), file: file, function: function, line: line)
    }

    // MARK: - Teardown

    /// Cancels the proactive refresh timer. Called from wrapper deinit via a
    /// fire-and-forget Task to hop onto the main actor.
    ///
    /// Other tasks (restoreTask, currentOperationTask, ongoingRefreshTask,
    /// pendingPersistTask) do not need explicit cancellation: they are either
    /// short-lived network/IO operations that exit promptly via [weak self],
    /// or they nil themselves via defer/await on normal completion.
    /// Only refreshTimer can sleep for up to (tokenLifetime - proactiveRefreshBuffer)
    /// seconds and warrants an explicit cancel when the manager is deallocated.
    func tearDown() {
        cancelRefreshTimer()
    }

    /// Awaits the initial session restore if it hasn't completed yet.
    private func awaitRestoreIfNeeded() async {
        await restoreTask?.value
        restoreTask = nil
    }

    // MARK: - Sign In

    func signIn(with credential: Provider.Credential) async {
        await awaitRestoreIfNeeded()
        guard !state.isLoading else { return }
        transition(to: .loading(.signingIn))

        let task = Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await self.withOperationTimeout {
                    try await self.provider.signIn(with: credential)
                }
                try Task.checkCancellation()
                try await self.persist(result)
                try Task.checkCancellation()
                self.transition(to: .signedIn(result.user))
                self.scheduleProactiveRefresh(for: result.token)
                self.emit(.info, "[\(self.provider.providerID)] Signed in.")
            } catch is CancellationError {
                // Provider threw CancellationError (e.g. user dismissed ASWebAuthenticationSession).
                // Transition to .failed(.cancelled) so the UI can react (re-enable the sign-in button,
                // show a message, etc.).
                self.transition(to: .failed(.cancelled))
                self.emit(.info, "[\(self.provider.providerID)] Sign-in cancelled.")
            } catch let error as SessionError {
                self.transition(to: .failed(error))
                self.emit(.error, "[\(self.provider.providerID)] Sign-in failed: \(error)")
            } catch {
                self.transition(to: .failed(.unknown(error.localizedDescription)))
            }
        }
        currentOperationTask = task
        await task.value
        currentOperationTask = nil
    }

    // MARK: - Sign Out

    func signOut() async {
        await awaitRestoreIfNeeded()
        guard state != .signedOut else { return }
        // Wait for any in-flight operation (signIn, reauthenticate) to settle first.
        // Cancelling mid-flight risks leaving a dangling server-side session: the provider
        // may have already issued tokens before the cancellation propagated, leaving tokens
        // the client can no longer revoke because cachedToken was never set.
        await currentOperationTask?.value
        currentOperationTask = nil
        // Drain any pending user-update persistence
        await pendingPersistTask?.value
        pendingPersistTask = nil
        // Cancel in-flight token refresh
        cancelRefreshTimer()
        ongoingRefreshTask?.cancel()
        ongoingRefreshTask = nil
        transition(to: .loading(.signingOut))
        if let token = cachedToken {
            do {
                try await withOperationTimeout {
                    try await self.provider.signOut(token: token)
                }
            } catch {
                log.warning("[\(self.provider.providerID)] Provider sign-out failed: \(error)")
            }
        }
        do {
            try await store.clear()
        } catch {
            log.warning("[\(self.provider.providerID)] Store clear failed during sign-out: \(error)")
        }
        cachedToken = nil
        transition(to: .signedOut)
        log.info("[\(self.provider.providerID)] Signed out.")
    }

    // MARK: - Re-authentication

    func reauthenticate(with credential: Provider.Credential) async throws {
        await awaitRestoreIfNeeded()
        guard let user = state.currentUser else { throw SessionError.sessionNotFound }
        guard !state.isLoading else {
            log.warning("[\(self.provider.providerID)] Reauthentication rejected — another operation in progress.")
            throw SessionError.providerError("Another operation is in progress")
        }
        transition(to: .loading(.reauthenticating))

        // Run inside currentOperationTask so signOut can cancel it if called concurrently.
        var thrownError: Error?
        let task = Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await self.withOperationTimeout {
                    try await self.provider.reauthenticate(user: user, with: credential)
                }
                try Task.checkCancellation()
                try await self.persist(result)
                try Task.checkCancellation()
                self.transition(to: .signedIn(result.user))
                self.emit(.info, "[\(self.provider.providerID)] Re-authenticated.")
            } catch is CancellationError {
                // Restore to .signedIn — the user is still authenticated.
                self.transition(to: .signedIn(user))
                self.emit(.info, "[\(self.provider.providerID)] Reauthentication cancelled.")
            } catch {
                self.transition(to: .signedIn(user))   // failed re-auth must not sign out
                thrownError = error
            }
        }
        currentOperationTask = task
        await task.value
        currentOperationTask = nil
        if let error = thrownError { throw error }
    }

    // MARK: - Update User (#5: tracked persist task, drained by signOut)

    func updateUser(_ user: SessionUser) {
        guard state.isAuthenticated, let token = cachedToken else { return }
        pendingPersistTask = Task { [weak self] in
            do {
                try await self?.store.save(token: token, user: user)
            } catch {
                guard let self else { return }
                self.emit(.warning, "[\(self.provider.providerID)] Store save failed during user update: \(error)")
            }
        }
        transition(to: .signedIn(user))
    }

    // MARK: - Refresh User

    func refreshUser() async throws {
        await awaitRestoreIfNeeded()
        guard state.isAuthenticated, let token = cachedToken else {
            throw SessionError.sessionNotFound
        }
        let result = try await withOperationTimeout {
            // currentUser: nil signals the provider to re-fetch the user profile.
            try await self.provider.refreshToken(token, currentUser: nil)
        }
        try await persist(result)
        transition(to: .signedIn(result.user))
        scheduleProactiveRefresh(for: result.token)
        emit(.info, "[\(self.provider.providerID)] User profile refreshed.")
    }

    // MARK: - Token Access

    func currentValidToken() async throws -> Provider.Token {
        await awaitRestoreIfNeeded()
        try await refreshIfNeeded()
        guard let token = cachedToken else { throw SessionError.sessionNotFound }
        return token
    }

    // MARK: - Convenience

    var currentUser:     SessionUser? { state.currentUser    }
    var isAuthenticated: Bool         { state.isAuthenticated }

    // MARK: - Private — Token Refresh (one-flight guarantee)

    private func refreshIfNeeded() async throws {
        guard state.isAuthenticated else {
            if state.isExpired { throw SessionError.sessionExpired }
            throw SessionError.sessionNotFound
        }

        if let ongoing = ongoingRefreshTask {
            _ = try await ongoing.value
            return
        }

        guard let token = cachedToken else { throw SessionError.sessionNotFound }
        guard token.isExpired || needsRefresh(token) else { return }

        try await startRefreshTask(token: token, currentUser: state.currentUser)
    }

    func forceRefreshToken() async throws {
        await awaitRestoreIfNeeded()
        guard state.isAuthenticated else {
            if state.isExpired { throw SessionError.sessionExpired }
            throw SessionError.sessionNotFound
        }

        // Join any already-running refresh rather than issuing a duplicate request.
        if let ongoing = ongoingRefreshTask {
            _ = try await ongoing.value
            return
        }

        guard let token = cachedToken else { throw SessionError.sessionNotFound }
        try await startRefreshTask(token: token, currentUser: state.currentUser)
    }

    /// Starts a one-flight refresh task and awaits its result.
    /// Callers are responsible for checking `ongoingRefreshTask` before calling.
    private func startRefreshTask(token: Provider.Token, currentUser: SessionUser?) async throws {
        let task = Task<Void, Error> { [weak self] in
            guard let self else { throw SessionError.unknown("Manager deallocated") }
            do {
                let result = try await self.provider.refreshToken(token, currentUser: currentUser)
                try await self.persist(result)
                await MainActor.run {
                    self.transition(to: .signedIn(result.user))
                    self.scheduleProactiveRefresh(for: result.token)
                }
                self.emit(.info, "[\(self.provider.providerID)] Token refreshed.")
            } catch {
                // Only treat the session as permanently invalid when the server has
                // explicitly rejected the credential (invalidCredentials). Network
                // errors, timeouts, and 5xx are transient — preserve the store so
                // the next currentValidToken() call can retry without forcing re-login.
                if case SessionError.invalidCredentials = error {
                    await MainActor.run {
                        // Preserve the current user in .expired — token expiry does
                        // not erase identity. Only an explicit signOut clears the user.
                        if let user = self.state.currentUser {
                            self.transition(to: .expired(user))
                        } else {
                            self.transition(to: .signedOut)
                        }
                    }
                    do {
                        // clearToken() preserves the user profile (including provider
                        // metadata such as a trusted-device cookie) so it is available
                        // on the next sign-in. Only the token is invalidated.
                        try await self.store.clearToken()
                    } catch {
                        self.emit(.warning, "[\(self.provider.providerID)] Store clearToken failed after permanent refresh failure: \(error)")
                    }
                    self.emit(.error, "[\(self.provider.providerID)] Refresh failed permanently: \(error)")
                } else {
                    self.emit(.warning, "[\(self.provider.providerID)] Refresh failed (transient): \(error)")
                }
                throw SessionError.tokenRefreshFailed
            }
        }

        ongoingRefreshTask = task
        defer { ongoingRefreshTask = nil }
        try await task.value
    }

    /// Returns true if the token is close enough to expiry that a refresh should be triggered,
    /// using the configured `proactiveRefreshBuffer` rather than the token's hardcoded threshold.
    private func needsRefresh(_ token: Provider.Token) -> Bool {
        guard let exp = token.expiresAt else { return false }
        return exp.timeIntervalSinceNow < configuration.proactiveRefreshBuffer
    }

    // MARK: - Private — Session Restore (#2: timeout protection, #6: native token fallback)

    private func restoreSession() async {
        var restoredUser: SessionUser?   // hoisted so the catch block can pass it to .expired
        do {
            // 1. Provider-native cache (e.g. Firebase SDK)
            let nativeToken: Provider.Token? = try await withOperationTimeout {
                await self.provider.currentToken()
            }
            if let nativeToken {
                if let stored = try? await store.load() {
                    cachedToken = nativeToken
                    transition(to: .signedIn(stored.user))
                    scheduleProactiveRefresh(for: nativeToken)
                    return
                }
                // #6: Provider has token but no stored user — try refresh to get user info.
                // currentUser is nil here; providers should fetch user profile if needed.
                do {
                    let result = try await withOperationTimeout {
                        try await self.provider.refreshToken(nativeToken, currentUser: nil)
                    }
                    try await persist(result)
                    transition(to: .signedIn(result.user))
                    scheduleProactiveRefresh(for: result.token)
                    return
                } catch {
                    log.warning("Provider token exists but no stored user and refresh failed — signing out.")
                    // Fall through to store-only path
                }
            }

            // 2. Our own CredentialStore
            guard let stored = try await store.load() else {
                transition(to: .signedOut); return
            }
            restoredUser = stored.user

            // Token was cleared by a prior permanent refresh failure (clearToken preserves
            // the user). Restore to .expired so identity is visible on the re-sign-in screen.
            guard let token = stored.token else {
                transition(to: .expired(stored.user)); return
            }
            cachedToken = token

            if token.isExpired {
                log.info("Stored token expired — attempting silent refresh.")
                let result = try await withOperationTimeout {
                    try await self.provider.refreshToken(token, currentUser: stored.user)
                }
                try await persist(result)
                transition(to: .signedIn(result.user))
                scheduleProactiveRefresh(for: result.token)
            } else {
                transition(to: .signedIn(stored.user))
                scheduleProactiveRefresh(for: token)
            }
        } catch {
            // Permanent auth rejection: stored credentials are invalid — clear them.
            // Transient failures (network, timeout): preserve the store so the user
            // isn't forced to re-login after a momentary connectivity issue.
            if case SessionError.invalidCredentials = error {
                log.warning("[\(self.provider.providerID)] Session restore failed permanently — clearing token.")
                do {
                    try await store.clearToken()
                } catch {
                    log.warning("[\(self.provider.providerID)] Store clearToken failed during restore cleanup: \(error)")
                }
                cachedToken = nil
                // Preserve the user in .expired if we loaded one — identity
                // survives a permanent token failure.
                if let user = restoredUser {
                    transition(to: .expired(user))
                } else {
                    transition(to: .signedOut)
                }
            } else {
                log.warning("[\(self.provider.providerID)] Session restore failed (transient) — signing out without clearing store. \(error)")
                cachedToken = nil
                transition(to: .signedOut)
            }
        }
    }

    private func persist(_ result: AuthResult<Provider.Token>) async throws {
        cachedToken = result.token
        try await store.save(token: result.token, user: result.user)
    }

    private func transition(to newState: SessionState) {
        guard state != newState else { return }
        state = newState
    }

    // MARK: - Private — Proactive Refresh Timer (#3: uses configured buffer)

    private func scheduleProactiveRefresh(for token: Provider.Token) {
        cancelRefreshTimer()
        guard !token.isExpired,
              !needsRefresh(token),
              let exp = token.expiresAt
        else { return }

        let fireIn = exp.timeIntervalSinceNow - configuration.proactiveRefreshBuffer
        guard fireIn > 0 else { return }

        refreshTimer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(fireIn * 1_000_000_000))
            guard !Task.isCancelled else { return }
            try? await self?.refreshIfNeeded()
        }
    }

    private func cancelRefreshTimer() {
        refreshTimer?.cancel()
        refreshTimer = nil
    }

    // MARK: - Private — Timeout Wrapper

    private nonisolated func withOperationTimeout<T: Sendable>(
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard let timeout = configuration.operationTimeout else {
            return try await operation()
        }
        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw SessionError.timeout
            }
            guard let result = try await group.next() else {
                throw SessionError.timeout
            }
            group.cancelAll()
            return result
        }
    }
}
