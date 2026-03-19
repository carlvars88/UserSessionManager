// MARK: - SessionManagerEngine.swift
//
// Internal engine that owns all session management business logic.
// No observation framework dependency — UserSessionManager (ObservableObject)
// and ObservableSessionManager (@Observable) are thin wrappers over this engine.

import Foundation
import os.log

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
    private var ongoingRefreshTask: Task<Provider.Token, Error>?

    // ── Session restore gate ──────────────────────────────────────────────
    private var restoreTask: Task<Void, Never>?

    // ── Proactive expiry timer ──────────────────────────────────────────────
    private var refreshTimer: Task<Void, Never>?

    // ── Logger ──────────────────────────────────────────────────────────────
    private let log = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "app",
        category: "SessionManager[\(Provider.self)]"
    )

    // MARK: Init

    init(
        provider: Provider,
        store: Store,
        configuration: SessionManagerConfiguration = SessionManagerConfiguration()
    ) {
        self.provider      = provider
        self.store         = store
        self.configuration = configuration
        restoreTask = Task { await self.restoreSession() }
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

        do {
            let result = try await withOperationTimeout {
                try await self.provider.signIn(with: credential)
            }
            try await persist(result)
            transition(to: .signedIn(result.user))
            scheduleProactiveRefresh(for: result.token)
            log.info("[\(self.provider.providerID)] Signed in — \(result.user.id)")
        } catch let error as SessionError {
            transition(to: .failed(error))
            log.error("[\(self.provider.providerID)] Sign-in failed: \(error)")
        } catch {
            transition(to: .failed(.unknown(error.localizedDescription)))
        }
    }

    // MARK: - Sign Out

    func signOut() async {
        await awaitRestoreIfNeeded()
        guard !state.isLoading else {
            log.warning("[\(self.provider.providerID)] Sign-out ignored — another operation in progress.")
            return
        }
        cancelRefreshTimer()
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
            log.warning("[\(self.provider.providerID)] Reauthentication ignored — another operation in progress.")
            return
        }
        transition(to: .loading(.reauthenticating))
        do {
            let result = try await withOperationTimeout {
                try await self.provider.reauthenticate(user: user, with: credential)
            }
            try await persist(result)
            transition(to: .signedIn(result.user))
            log.info("[\(self.provider.providerID)] Re-authenticated: \(result.user.id)")
        } catch {
            transition(to: .signedIn(user))   // failed re-auth must not sign out
            throw error
        }
    }

    // MARK: - Update User

    func updateUser(_ user: SessionUser) {
        guard state.isAuthenticated, let token = cachedToken else { return }
        Task { [weak self] in
            do {
                try await self?.store.save(token: token, user: user)
            } catch {
                self?.log.warning("[\(self?.provider.providerID ?? "??")] Store save failed during user update: \(error)")
            }
        }
        transition(to: .signedIn(user))
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
        guard state.isAuthenticated else { throw SessionError.sessionNotFound }

        if let ongoing = ongoingRefreshTask {
            _ = try await ongoing.value
            return
        }

        guard let token = cachedToken else { throw SessionError.sessionNotFound }
        guard token.needsProactiveRefresh else { return }

        let task = Task<Provider.Token, Error> { [weak self] in
            guard let self else { throw SessionError.unknown("Manager deallocated") }
            do {
                let result = try await self.provider.refreshToken(token)
                try await self.persist(result)
                await MainActor.run {
                    self.transition(to: .signedIn(result.user))
                    self.scheduleProactiveRefresh(for: result.token)
                }
                self.log.info("[\(self.provider.providerID)] Token refreshed.")
                return result.token
            } catch {
                await MainActor.run { self.transition(to: .expired) }
                do {
                    try await self.store.clear()
                } catch {
                    self.log.warning("[\(self.provider.providerID)] Store clear failed after refresh failure: \(error)")
                }
                self.log.error("[\(self.provider.providerID)] Refresh failed: \(error)")
                throw SessionError.tokenRefreshFailed
            }
        }

        ongoingRefreshTask = task
        defer { ongoingRefreshTask = nil }
        _ = try await task.value
    }

    // MARK: - Private — Session Restore

    private func restoreSession() async {
        do {
            if let nativeToken = await provider.currentToken() {
                cachedToken = nativeToken
                if let stored = try? await store.load() {
                    transition(to: .signedIn(stored.user))
                    scheduleProactiveRefresh(for: nativeToken)
                    return
                }
            }

            guard let stored = try await store.load() else {
                transition(to: .signedOut); return
            }
            cachedToken = stored.token

            if stored.token.isExpired {
                log.info("Stored token expired — attempting silent refresh.")
                let result = try await provider.refreshToken(stored.token)
                try await persist(result)
                transition(to: .signedIn(result.user))
                scheduleProactiveRefresh(for: result.token)
            } else {
                transition(to: .signedIn(stored.user))
                scheduleProactiveRefresh(for: stored.token)
            }
        } catch {
            log.warning("Session restore failed — signing out. \(error)")
            do {
                try await store.clear()
            } catch {
                log.warning("[\(self.provider.providerID)] Store clear failed during restore cleanup: \(error)")
            }
            cachedToken = nil
            transition(to: .signedOut)
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

    // MARK: - Private — Proactive Refresh Timer

    private func scheduleProactiveRefresh(for token: Provider.Token) {
        cancelRefreshTimer()
        guard token.needsProactiveRefresh == false,
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
