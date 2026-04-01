// MARK: - Tests/UserSessionManagerTests.swift

import XCTest
@testable import SessionManager

// Default SUT — BearerToken via MockIdentityProvider
private typealias SUT = UserSessionManager<MockIdentityProvider, InMemoryCredentialStore<BearerToken>>

// Opaque SUT — OpaqueSessionToken via MockOpaqueProvider
private typealias OpaqueSUT = UserSessionManager<MockOpaqueProvider, InMemoryCredentialStore<OpaqueSessionToken>>

final class UserSessionManagerTests: XCTestCase {

    // MARK: - Helpers

    @MainActor
    private func makeSUT(
        failSignIn:    Bool         = false,
        failRefresh:   Bool         = false,
        tokenLifetime: TimeInterval = 3600
    ) -> SUT {
        SUT(
            provider: MockIdentityProvider(
                simulatedLatency: .zero,
                shouldFailSignIn:  failSignIn,
                shouldFailRefresh: failRefresh,
                tokenLifetime:     tokenLifetime
            ),
            store: InMemoryCredentialStore<BearerToken>()
        )
    }

    @MainActor
    private func makeOpaqueSUT(failSignIn: Bool = false) -> OpaqueSUT {
        OpaqueSUT(
            provider: MockOpaqueProvider(shouldFailSignIn: failSignIn),
            store:    InMemoryCredentialStore<OpaqueSessionToken>()
        )
    }

    private func validCredential() -> EmailPasswordCredential {
        EmailPasswordCredential(email: "test@example.com", password: "password123")
    }

    // MARK: - Initial State

    @MainActor
    func test_initialState_isRestoringSession() {
        let sut = makeSUT()
        XCTAssertEqual(sut.state, .loading(.restoringSession))
        XCTAssertTrue(sut.state.isLoading)
        XCTAssertNil(sut.state.error)
        XCTAssertNil(sut.state.currentUser)
    }

    // MARK: - Sign In (BearerToken)

    @MainActor
    func test_signIn_withValidCredential_transitionsToSignedIn() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())

        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertNotNil(sut.state.currentUser)
        XCTAssertNil(sut.state.error)
    }

    @MainActor
    func test_signIn_withInvalidEmail_transitionsToFailed() async {
        let sut = makeSUT()
        await sut.signIn(with: EmailPasswordCredential(email: "notanemail", password: "password123"))

        guard case .failed(let error) = sut.state else {
            XCTFail("Expected .failed, got \(sut.state)"); return
        }
        XCTAssertEqual(error, .invalidCredentials)
    }

    @MainActor
    func test_signIn_whenProviderFails_transitionsToFailed() async {
        let sut = makeSUT(failSignIn: true)
        await sut.signIn(with: validCredential())
        XCTAssertEqual(sut.state, .failed(.invalidCredentials))
    }

    @MainActor
    func test_signIn_cancelled_transitionsToFailedCancelled() async {
        // Simulates the user dismissing ASWebAuthenticationSession mid-flow.
        // The provider throws CancellationError → state must be .failed(.cancelled).
        struct CancellingProvider: IdentityProvider, Sendable {
            typealias Credential = EmailPasswordCredential
            typealias Token      = BearerToken
            let providerID = "cancelling"
            func signIn(with c: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
                throw CancellationError()
            }
            func refreshToken(_ t: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> {
                throw SessionError.tokenRefreshFailed
            }
            func signOut(token: BearerToken) async throws {}
        }

        let sut = UserSessionManager(
            provider: CancellingProvider(),
            store:    InMemoryCredentialStore<BearerToken>()
        )
        await sut.signIn(with: validCredential())

        XCTAssertEqual(sut.state, .failed(.cancelled))
        XCTAssertFalse(sut.state.isAuthenticated)
    }

    @MainActor
    func test_reauthenticate_cancelled_remainsSignedIn() async {
        // Simulates the user dismissing a biometric or re-auth prompt mid-flow.
        // CancellationError during reauthenticate must not sign the user out.
        struct CancellingProvider: IdentityProvider, Sendable {
            typealias Credential = EmailPasswordCredential
            typealias Token      = BearerToken
            let providerID = "cancelling-reauth"
            var callCount = 0
            func signIn(with c: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
                AuthResult(user: SessionUser(id: "u1", displayName: "User"),
                           token: BearerToken(accessToken: "tok", expiresAt: Date().addingTimeInterval(3600)))
            }
            func reauthenticate(user: SessionUser, with c: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
                throw CancellationError()
            }
            func refreshToken(_ t: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> {
                throw SessionError.tokenRefreshFailed
            }
            func signOut(token: BearerToken) async throws {}
        }

        let sut = UserSessionManager(
            provider: CancellingProvider(),
            store:    InMemoryCredentialStore<BearerToken>()
        )
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
        let user = sut.state.currentUser

        try? await sut.reauthenticate(with: validCredential())

        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertEqual(sut.state.currentUser, user)
    }

    @MainActor
    func test_signIn_whileLoading_isIgnored() async {
        let sut = makeSUT()
        // First signIn transitions to .loading — second should be rejected
        await sut.signIn(with: validCredential())
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
    }

    // MARK: - Sign In (OpaqueSessionToken)
    //
    // Key proof: the manager works identically with a completely different token shape.
    // The compiler enforces Store.Token == Provider.Token — no runtime cast needed.

    @MainActor
    func test_opaqueProvider_signIn_transitionsToSignedIn() async {
        let sut = makeOpaqueSUT()
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertNotNil(sut.state.currentUser)
    }

    @MainActor
    func test_opaqueProvider_signIn_failure_transitionsToFailed() async {
        let sut = makeOpaqueSUT(failSignIn: true)
        await sut.signIn(with: validCredential())
        XCTAssertEqual(sut.state, .failed(.invalidCredentials))
    }

    @MainActor
    func test_opaqueProvider_currentValidToken_returnsOpaqueToken() async throws {
        let sut = makeOpaqueSUT()
        await sut.signIn(with: validCredential())
        let token = try await sut.currentValidToken()
        // Token is OpaqueSessionToken — no accessToken, no scopes, just a value
        XCTAssertFalse(token.value.isEmpty)
    }

    // MARK: - Sign Out

    @MainActor
    func test_signOut_transitionsToSignedOut() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        await sut.signOut()
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.state.currentUser)
    }

    @MainActor
    func test_signOut_whenAlreadySignedOut_isNoOp() async {
        let store = InMemoryCredentialStore<BearerToken>()
        let provider = MockIdentityProvider(simulatedLatency: .zero)
        let sut = SUT(provider: provider, store: store)
        // Never sign in — state is .signedOut after restore
        await sut.signOut()
        XCTAssertEqual(sut.state, .signedOut)
        // Store must remain untouched (nothing to clear)
        let stored = try? await store.load()
        XCTAssertNil(stored)
    }

    // MARK: - Token (SessionTokenProviding)

    @MainActor
    func test_currentValidToken_returnsBearerToken() async throws {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        let token: BearerToken = try await sut.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
        XCTAssertNotNil(token.refreshToken)
    }

    @MainActor
    func test_currentValidToken_whenNotSignedIn_throws() async {
        let sut = makeSUT()
        do {
            _ = try await sut.currentValidToken()
            XCTFail("Expected sessionNotFound")
        } catch SessionError.sessionNotFound { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    @MainActor
    func test_expiredToken_silentlyRefreshedByCurrentValidToken() async throws {
        let sut = makeSUT(tokenLifetime: -1)   // already expired at sign-in
        await sut.signIn(with: validCredential())
        let token: BearerToken = try await sut.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
    }

    @MainActor
    func test_refreshFails_transitionsToExpired() async {
        let sut = makeSUT(failRefresh: true, tokenLifetime: -1)
        await sut.signIn(with: validCredential())
        do {
            _ = try await sut.currentValidToken()
            XCTFail("Expected tokenRefreshFailed")
        } catch {
            XCTAssertEqual(sut.state, .expired)
        }
    }

    @MainActor
    func test_refreshFails_permanently_clearsStore() async throws {
        // invalidCredentials means the server explicitly rejected the token —
        // session is gone, store must be wiped.
        let store = InMemoryCredentialStore<BearerToken>()
        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .invalidCredentials,
            tokenLifetime: -1
        )
        let sut = SUT(provider: provider, store: store)
        await sut.signIn(with: validCredential())

        do { _ = try await sut.currentValidToken() } catch { }

        XCTAssertEqual(sut.state, .expired)
        let stored = try await store.load()
        XCTAssertNil(stored, "Store must be cleared after permanent refresh rejection")
    }

    @MainActor
    func test_currentValidToken_whenExpired_throwsSessionExpired() async {
        // After a permanent refresh failure the state is .expired.
        // A subsequent currentValidToken() call must throw .sessionExpired,
        // not .sessionNotFound, so callers can distinguish the two cases.
        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .invalidCredentials,
            tokenLifetime: -1
        )
        let sut = SUT(provider: provider, store: InMemoryCredentialStore())
        await sut.signIn(with: validCredential())
        do { _ = try await sut.currentValidToken() } catch { }   // triggers .expired transition

        XCTAssertEqual(sut.state, .expired)

        do {
            _ = try await sut.currentValidToken()
            XCTFail("Expected sessionExpired to be thrown")
        } catch let error as SessionError {
            XCTAssertEqual(error, .sessionExpired)
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    @MainActor
    func test_refreshFails_transiently_preservesSessionAndStore() async throws {
        // A transient error (timeout, server 503, etc.) must not wipe the store
        // or transition to .expired — the next call should be able to retry.
        let store = InMemoryCredentialStore<BearerToken>()
        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .timeout,   // transient
            tokenLifetime: -1
        )
        let sut = SUT(provider: provider, store: store)
        await sut.signIn(with: validCredential())

        do { _ = try await sut.currentValidToken() } catch { }

        XCTAssertTrue(sut.state.isAuthenticated, "State must stay .signedIn after transient refresh failure")
        let stored = try await store.load()
        XCTAssertNotNil(stored, "Store must not be cleared after transient refresh failure")
    }

    @MainActor
    func test_sessionRestore_expiredToken_transientRefreshFailure_signedOutButStorePreserved() async throws {
        // On app relaunch with an expired stored token, a transient refresh failure
        // should sign out without clearing the store — credentials survive for next launch.
        let store = InMemoryCredentialStore<BearerToken>()
        let expiredToken = BearerToken(
            accessToken: "old-access",
            refreshToken: "old-refresh",
            expiresAt: Date().addingTimeInterval(-100)  // already expired
        )
        try await store.save(token: expiredToken, user: SessionUser(id: "u1", displayName: "User"))

        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .timeout,   // transient — no network on launch
            tokenLifetime: -1
        )
        let sut = SUT(provider: provider, store: store)
        // Trigger restore completion
        _ = try? await sut.currentValidToken()

        XCTAssertEqual(sut.state, .signedOut)
        let stored = try await store.load()
        XCTAssertNotNil(stored, "Store must survive a transient restore failure")
    }

    @MainActor
    func test_sessionRestore_expiredToken_permanentRefreshFailure_clearsStore() async throws {
        // On app relaunch with an expired stored token, a permanent rejection
        // must clear the store — stale credentials should not persist.
        let store = InMemoryCredentialStore<BearerToken>()
        let expiredToken = BearerToken(
            accessToken: "revoked-access",
            refreshToken: "revoked-refresh",
            expiresAt: Date().addingTimeInterval(-100)
        )
        try await store.save(token: expiredToken, user: SessionUser(id: "u1", displayName: "User"))

        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .invalidCredentials,  // permanent — token was revoked
            tokenLifetime: -1
        )
        let sut = SUT(provider: provider, store: store)
        _ = try? await sut.currentValidToken()

        XCTAssertEqual(sut.state, .signedOut)
        let stored = try await store.load()
        XCTAssertNil(stored, "Store must be cleared after permanent restore failure")
    }

    @MainActor
    func test_sessionRestore_validStoredToken_restoresWithoutRefresh() async throws {
        // A valid stored token must restore the session without hitting the network.
        // shouldFailRefresh: true acts as a tripwire — if refresh is called the test fails.
        let store = InMemoryCredentialStore<BearerToken>()
        let validToken = BearerToken(
            accessToken: "stored-access",
            expiresAt: Date().addingTimeInterval(3600)
        )
        try await store.save(token: validToken, user: SessionUser(id: "u1", displayName: "User"))

        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .invalidCredentials   // would clear store if called
        )
        let sut = SUT(provider: provider, store: store)
        _ = try? await sut.currentValidToken()

        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertEqual(sut.state.currentUser?.id, "u1")
        let token = try await sut.currentValidToken()
        XCTAssertEqual(token.accessToken, "stored-access")
    }

    @MainActor
    func test_sessionRestore_expiredStoredToken_silentRefreshSucceeds_restoresSession() async throws {
        // On app relaunch with an expired stored token, a successful silent refresh
        // must restore the session with the new token.
        let store = InMemoryCredentialStore<BearerToken>()
        let expiredToken = BearerToken(
            accessToken: "old-access",
            expiresAt: Date().addingTimeInterval(-100)
        )
        try await store.save(token: expiredToken, user: SessionUser(id: "u1", displayName: "User"))

        let provider = MockIdentityProvider(simulatedLatency: .zero, shouldFailRefresh: false)
        let sut = SUT(provider: provider, store: store)
        _ = try? await sut.currentValidToken()

        XCTAssertTrue(sut.state.isAuthenticated)
        let token = try await sut.currentValidToken()
        XCTAssertNotEqual(token.accessToken, "old-access")
    }

    @MainActor
    func test_sessionRestore_nativeToken_noStoredUser_refreshesToGetUser() async throws {
        // Path #6: provider has a cached native token but no user was ever persisted
        // (e.g. first launch after an app update that added SessionManager).
        // Engine must call refreshToken to recover user info.
        let store = InMemoryCredentialStore<BearerToken>()

        let provider = MockIdentityProvider(simulatedLatency: .zero, shouldFailRefresh: false)
        provider.nativeToken = BearerToken(
            accessToken: "native-access",
            expiresAt: Date().addingTimeInterval(3600)
        )
        let sut = SUT(provider: provider, store: store)
        _ = try? await sut.currentValidToken()

        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertEqual(sut.state.currentUser?.id, provider.fixedUser.id)
    }

    @MainActor
    func test_freshToken_noUnnecessaryRefresh() async throws {
        let sut = makeSUT(failRefresh: true, tokenLifetime: 3600)
        await sut.signIn(with: validCredential())
        // Must not throw — token is fresh, no refresh attempt made
        let token: BearerToken = try await sut.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
    }

    // MARK: - Update User

    @MainActor
    func test_updateUser_reflectsInState() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        sut.updateUser(SessionUser(id: "mock-001", displayName: "Updated", email: "new@b.com"))
        XCTAssertEqual(sut.state.currentUser?.displayName, "Updated")
    }

    @MainActor
    func test_refreshUser_fetchesFreshProfileFromProvider() async throws {
        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            fixedUser: SessionUser(id: "mock-001", displayName: "Original Name")
        )
        let sut = SUT(provider: provider, store: InMemoryCredentialStore())
        await sut.signIn(with: validCredential())
        XCTAssertEqual(sut.state.currentUser?.displayName, "Original Name")

        // Simulate a server-side profile change
        provider.fixedUser = SessionUser(id: "mock-001", displayName: "Updated Name", email: "new@example.com")

        try await sut.refreshUser()

        XCTAssertEqual(sut.state.currentUser?.displayName, "Updated Name")
        XCTAssertEqual(sut.state.currentUser?.email, "new@example.com")
    }

    @MainActor
    func test_refreshUser_whenNotSignedIn_throws() async {
        let sut = makeSUT()
        // Wait for restore to settle to .signedOut
        _ = try? await sut.currentValidToken()
        do {
            try await sut.refreshUser()
            XCTFail("Expected sessionNotFound")
        } catch SessionError.sessionNotFound { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    // MARK: - Force Refresh Token

    @MainActor
    func test_forceRefreshToken_refreshesEvenWhenTokenIsValid() async throws {
        // Token lifetime is 1 hour — not expired, not near expiry.
        // currentValidToken() would return it without touching the provider.
        // forceRefreshToken() must call the provider regardless.
        let provider = MockIdentityProvider(simulatedLatency: .zero, tokenLifetime: 3600)
        let sut = SUT(provider: provider, store: InMemoryCredentialStore<BearerToken>())
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.isAuthenticated)
        XCTAssertEqual(provider.refreshCallCount, 0)

        try await sut.forceRefreshToken()

        XCTAssertEqual(provider.refreshCallCount, 1)
        XCTAssertTrue(sut.isAuthenticated)
    }

    @MainActor
    func test_forceRefreshToken_whenNotSignedIn_throwsSessionNotFound() async {
        let sut = makeSUT()
        _ = try? await sut.currentValidToken() // drain restore
        do {
            try await sut.forceRefreshToken()
            XCTFail("Expected sessionNotFound")
        } catch SessionError.sessionNotFound { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    @MainActor
    func test_forceRefreshToken_permanentFailure_transitionsToExpired() async throws {
        let sut = makeSUT(failRefresh: false)
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.isAuthenticated)

        // Switch provider to permanent failure after sign-in
        // (simulates server-side revocation between requests)
        let provider = MockIdentityProvider(
            simulatedLatency: .zero,
            shouldFailRefresh: true,
            refreshError: .invalidCredentials
        )
        let sut2 = SUT(provider: provider, store: InMemoryCredentialStore<BearerToken>())
        await sut2.signIn(with: validCredential())
        provider.shouldFailRefresh = true

        do {
            try await sut2.forceRefreshToken()
            XCTFail("Expected tokenRefreshFailed")
        } catch SessionError.tokenRefreshFailed { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }

        XCTAssertEqual(sut2.state, .expired)
    }

    @MainActor
    func test_updateUser_whenNotSignedIn_isNoOp() {
        let sut = makeSUT()
        sut.updateUser(SessionUser(id: "x", displayName: "Ghost"))
        XCTAssertNil(sut.state.currentUser)
    }

    // MARK: - where clause enforced at compile time
    //
    // The following would be a BUILD ERROR — proves the constraint works:
    //
    //   UserSessionManager(
    //       provider: MockIdentityProvider(),           // Token = BearerToken
    //       store:    InMemoryCredentialStore<OpaqueSessionToken>()  // Token ≠ BearerToken
    //   )
    //   // error: type 'InMemoryCredentialStore<OpaqueSessionToken>' does not
    //   //        conform to 'CredentialStore' — Store.Token != Provider.Token

    // MARK: - APIClient caller split

    @MainActor
    func test_apiClient_dependsOnlyOnSessionTokenProviding() async throws {

        struct APIClient {
            let tokens: any SessionTokenProviding<BearerToken>

            func authorizationHeader() async throws -> String {
                let token = try await tokens.currentValidToken()
                return "\(token.tokenType) \(token.accessToken)"
            }
        }

        // 1. Real manager
        let manager = await UserSessionManager(
            provider: MockIdentityProvider(simulatedLatency: .zero),
            store:    InMemoryCredentialStore<BearerToken>()
        )
        await manager.signIn(with: EmailPasswordCredential(email: "a@b.com", password: "pass123"))
        let header = try await APIClient(tokens: manager).authorizationHeader()
        XCTAssertTrue(header.hasPrefix("Bearer mock-access-"))

        // 2. MockTokenProvider — no session manager at all
        let stub = MockTokenProvider<BearerToken>(.success(
            BearerToken(accessToken: "test-token")
        ))
        let stubHeader = try await APIClient(tokens: stub).authorizationHeader()
        XCTAssertEqual(stubHeader, "Bearer test-token")
    }

    // MARK: - AnyTokenProvider

    func test_anyTokenProvider_bearer_extractsAccessToken() async throws {
        let manager = await UserSessionManager(
            provider: MockIdentityProvider(simulatedLatency: .zero),
            store:    InMemoryCredentialStore<BearerToken>()
        )
        await manager.signIn(with: EmailPasswordCredential(email: "a@b.com", password: "pass123"))
        let anyProvider = AnyTokenProvider(manager)
        let raw = try await anyProvider.currentRawToken()
        XCTAssertNotNil(raw)
        XCTAssertTrue(raw!.hasPrefix("mock-access-"))
    }

    func test_anyTokenProvider_opaque_extractsValue() async throws {
        let manager = await UserSessionManager(
            provider: MockOpaqueProvider(),
            store:    InMemoryCredentialStore<OpaqueSessionToken>()
        )
        await manager.signIn(with: EmailPasswordCredential(email: "a@b.com", password: "pass123"))
        let anyProvider = AnyTokenProvider(manager)
        let raw = try await anyProvider.currentRawToken()
        XCTAssertNotNil(raw)
        XCTAssertTrue(raw!.hasPrefix("opaque-"))
    }

    // MARK: - MockTokenProvider

    @MainActor
    func test_mockTokenProvider_success() async throws {
        let provider = MockTokenProvider<BearerToken>(.success(BearerToken(accessToken: "tok")))
        let token = try await provider.currentValidToken()
        XCTAssertEqual(token.accessToken, "tok")
    }

    @MainActor
    func test_mockTokenProvider_failure() async {
        let provider = MockTokenProvider<BearerToken>(.failure(.sessionNotFound))
        do {
            _ = try await provider.currentValidToken()
            XCTFail("Expected failure")
        } catch SessionError.sessionNotFound { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    // MARK: - Configuration

    @MainActor
    func test_customConfiguration_isApplied() {
        let config = SessionManagerConfiguration(proactiveRefreshBuffer: 120, operationTimeout: 10)
        let sut = SUT(
            provider: MockIdentityProvider(simulatedLatency: .zero),
            store: InMemoryCredentialStore<BearerToken>(),
            configuration: config
        )
        XCTAssertEqual(sut.configuration.proactiveRefreshBuffer, 120)
        XCTAssertEqual(sut.configuration.operationTimeout, 10)
    }

    @MainActor
    func test_defaultConfiguration_has30sTimeout() {
        let sut = makeSUT()
        XCTAssertEqual(sut.configuration.operationTimeout, 30)
        XCTAssertEqual(sut.configuration.proactiveRefreshBuffer, 60)
    }

    // MARK: - Operation Deduplication

    @MainActor
    func test_signOut_whileSignInLoading_waitsForSignInThenSignsOut() async {
        // signOut must wait for an in-flight signIn to settle before proceeding.
        // Cancelling mid-flight risks a dangling server-side session if the provider
        // already issued tokens before the cancellation reached it.
        let slowProvider = MockIdentityProvider(
            simulatedLatency: .seconds(2),
            shouldFailSignIn: false,
            tokenLifetime: 3600
        )
        let sut = SUT(
            provider: slowProvider,
            store: InMemoryCredentialStore<BearerToken>()
        )
        // Start signIn in the background — it will sit in .loading(.signingIn)
        let signInTask = Task { await sut.signIn(with: validCredential()) }
        try? await Task.sleep(nanoseconds: 100_000_000) // 0.1s
        XCTAssertEqual(sut.state, .loading(.signingIn))
        // signOut waits for signIn to complete, then signs out — final state is .signedOut
        await sut.signOut()
        await signInTask.value
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertFalse(sut.state.isAuthenticated)
    }

    @MainActor
    func test_reauthenticate_whileNotSignedIn_throws() async {
        let sut = makeSUT()
        do {
            try await sut.reauthenticate(with: validCredential())
            XCTFail("Expected sessionNotFound")
        } catch SessionError.sessionNotFound { /* expected */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    @MainActor
    func test_reauthenticate_success_updatesState() async throws {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)

        try await sut.reauthenticate(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertNotNil(sut.state.currentUser)
    }

    @MainActor
    func test_reauthenticate_failure_remainsSignedIn() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
        let user = sut.state.currentUser

        // Fail reauthentication — should stay signed in with same user
        do {
            try await sut.reauthenticate(
                with: EmailPasswordCredential(email: "notanemail", password: "password123")
            )
            XCTFail("Expected error")
        } catch {
            XCTAssertTrue(sut.state.isAuthenticated)
            XCTAssertEqual(sut.state.currentUser, user)
        }
    }

    // MARK: - Timeout

    @MainActor
    func test_signIn_withSlowProvider_timesOut() async {
        let slowProvider = MockIdentityProvider(
            simulatedLatency: .seconds(5),
            shouldFailSignIn: false,
            tokenLifetime: 3600
        )
        let sut = SUT(
            provider: slowProvider,
            store: InMemoryCredentialStore<BearerToken>(),
            configuration: SessionManagerConfiguration(operationTimeout: 0.1)
        )
        await sut.signIn(with: validCredential())

        guard case .failed(let error) = sut.state else {
            XCTFail("Expected .failed, got \(sut.state)"); return
        }
        XCTAssertEqual(error, .timeout)
    }

    @MainActor
    func test_signIn_withNoTimeout_waitsIndefinitely() async {
        let sut = SUT(
            provider: MockIdentityProvider(simulatedLatency: .zero),
            store: InMemoryCredentialStore<BearerToken>(),
            configuration: SessionManagerConfiguration(operationTimeout: nil)
        )
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
    }

    // MARK: - Proactive Refresh Timer

    @MainActor
    func test_proactiveRefresh_triggersBeforeExpiry() async throws {
        // Token expires in 2 seconds, buffer is 1.5s → timer fires at 0.5s
        let sut = SUT(
            provider: MockIdentityProvider(
                simulatedLatency: .zero,
                shouldFailRefresh: false,
                tokenLifetime: 2
            ),
            store: InMemoryCredentialStore<BearerToken>(),
            configuration: SessionManagerConfiguration(
                proactiveRefreshBuffer: 1.5,
                operationTimeout: 5
            )
        )
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)

        let firstToken = try await sut.currentValidToken()

        // Wait for proactive refresh to fire (timer should fire at ~0.5s)
        try await Task.sleep(nanoseconds: 1_500_000_000)

        let secondToken = try await sut.currentValidToken()
        // After proactive refresh, we should have a different access token
        XCTAssertNotEqual(firstToken.accessToken, secondToken.accessToken)
    }

    // MARK: - AuthSessionToken.expiresAt protocol

    func test_bearerToken_expiresAt_conformsToProtocol() {
        let date = Date.now.addingTimeInterval(3600)
        let token = BearerToken(accessToken: "a", expiresAt: date)
        // expiresAt is now a protocol requirement, not just a stored property
        let protocolToken: any AuthSessionToken = token
        XCTAssertEqual(protocolToken.expiresAt, date)
    }

    func test_opaqueToken_expiresAt_conformsToProtocol() {
        let date = Date.now.addingTimeInterval(86400)
        let token = OpaqueSessionToken(value: "v", expiresAt: date)
        let protocolToken: any AuthSessionToken = token
        XCTAssertEqual(protocolToken.expiresAt, date)
    }

    func test_cookieToken_expiresAt_conformsToProtocol() {
        let date = Date.now.addingTimeInterval(3600)
        let token = CookieToken(cookieName: "sid", expiresAt: date)
        let protocolToken: any AuthSessionToken = token
        XCTAssertEqual(protocolToken.expiresAt, date)
    }

    func test_tokenWithNoExpiry_returnsNilExpiresAt() {
        let token = BearerToken(accessToken: "a")
        XCTAssertNil(token.expiresAt)
        XCTAssertFalse(token.isExpired)
    }

    // MARK: - SessionError.timeout

    func test_timeoutError_hasDescription() {
        let error = SessionError.timeout
        XCTAssertEqual(error.errorDescription, "The operation timed out. Please try again.")
    }

    // MARK: - Keychain Store

    func test_keychainStore_saveAndLoad_roundTrips() async throws {
        let store = KeychainCredentialStore<BearerToken>(namespace: "com.test.sessionmanager.\(UUID().uuidString)")
        let token = BearerToken(accessToken: "acc", refreshToken: "ref", expiresAt: Date(timeIntervalSince1970: 2000000000))
        let user = SessionUser(id: "u1", displayName: "Test User", email: "t@e.com")

        try await store.save(token: token, user: user)
        let loaded = try await store.load()

        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded?.token.accessToken, "acc")
        XCTAssertEqual(loaded?.token.refreshToken, "ref")
        XCTAssertEqual(loaded?.user.id, "u1")
        XCTAssertEqual(loaded?.user.displayName, "Test User")

        // Cleanup
        try await store.clear()
    }

    func test_keychainStore_overwrite_getsLatest() async throws {
        let store = KeychainCredentialStore<BearerToken>(namespace: "com.test.sessionmanager.\(UUID().uuidString)")
        let user = SessionUser(id: "u1", displayName: "User")

        try await store.save(token: BearerToken(accessToken: "first"), user: user)
        try await store.save(token: BearerToken(accessToken: "second"), user: user)

        let loaded = try await store.load()
        XCTAssertEqual(loaded?.token.accessToken, "second")

        try await store.clear()
    }

    func test_keychainStore_clear_removesData() async throws {
        let store = KeychainCredentialStore<BearerToken>(namespace: "com.test.sessionmanager.\(UUID().uuidString)")
        let token = BearerToken(accessToken: "a")
        let user = SessionUser(id: "u1", displayName: "User")

        try await store.save(token: token, user: user)
        try await store.clear()

        let loaded = try await store.load()
        XCTAssertNil(loaded)
    }

    func test_keychainStore_loadEmpty_returnsNil() async throws {
        let store = KeychainCredentialStore<BearerToken>(namespace: "com.test.sessionmanager.\(UUID().uuidString)")
        let loaded = try await store.load()
        XCTAssertNil(loaded)
    }

    func test_keychainStore_opaqueToken_roundTrips() async throws {
        let store = KeychainCredentialStore<OpaqueSessionToken>(namespace: "com.test.sessionmanager.\(UUID().uuidString)")
        let token = OpaqueSessionToken(value: "opaque-value", expiresAt: Date(timeIntervalSince1970: 2000000000))
        let user = SessionUser(id: "u2", displayName: "Opaque User")

        try await store.save(token: token, user: user)
        let loaded = try await store.load()

        XCTAssertEqual(loaded?.token.value, "opaque-value")
        XCTAssertEqual(loaded?.user.displayName, "Opaque User")

        try await store.clear()
    }

    func test_keychainStore_cookieToken_roundTrips() async throws {
        let store = KeychainCredentialStore<CookieToken>(namespace: "com.test.sessionmanager.\(UUID().uuidString)")
        let token = CookieToken(cookieName: "session_id", expiresAt: Date(timeIntervalSince1970: 2000000000))
        let user = SessionUser(id: "u3", displayName: "Cookie User")

        try await store.save(token: token, user: user)
        let loaded = try await store.load()

        XCTAssertEqual(loaded?.token.cookieName, "session_id")
        XCTAssertEqual(loaded?.user.id, "u3")

        try await store.clear()
    }

    // MARK: - Concurrent Operations

    @MainActor
    func test_signIn_thenImmediateTokenAccess_succeeds() async throws {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        // Immediately request token — should not race with internal state
        let token = try await sut.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
        XCTAssertTrue(sut.state.isAuthenticated)
    }

    @MainActor
    func test_multipleConcurrentTokenRequests_allSucceed() async throws {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())

        // Fire multiple concurrent token requests
        async let t1 = sut.currentValidToken()
        async let t2 = sut.currentValidToken()
        async let t3 = sut.currentValidToken()

        let tokens = try await [t1, t2, t3]
        for token in tokens {
            XCTAssertFalse(token.accessToken.isEmpty)
        }
    }

    @MainActor
    func test_signOut_cancelsRefreshTimer_andClearsState() async throws {
        // Token expires in 2s, buffer 1.5s → timer fires at 0.5s
        let sut = SUT(
            provider: MockIdentityProvider(
                simulatedLatency: .zero,
                shouldFailRefresh: false,
                tokenLifetime: 2
            ),
            store: InMemoryCredentialStore<BearerToken>(),
            configuration: SessionManagerConfiguration(
                proactiveRefreshBuffer: 1.5,
                operationTimeout: 5
            )
        )
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)

        // Sign out before the refresh timer fires
        await sut.signOut()
        XCTAssertEqual(sut.state, .signedOut)

        // Wait past when the timer would have fired
        try await Task.sleep(nanoseconds: 1_000_000_000)

        // State should still be signedOut — timer was cancelled
        XCTAssertEqual(sut.state, .signedOut)
    }

    @MainActor
    func test_concurrentRefresh_deduplicates() async throws {
        // Token already expired → every currentValidToken triggers refresh
        let sut = makeSUT(tokenLifetime: -1)
        await sut.signIn(with: validCredential())

        // Fire multiple concurrent token requests that all need refresh
        async let t1 = sut.currentValidToken()
        async let t2 = sut.currentValidToken()

        let tokens = try await [t1, t2]
        // Both should succeed (one-flight guarantee means only one refresh happens)
        for token in tokens {
            XCTAssertFalse(token.accessToken.isEmpty)
        }
        XCTAssertTrue(sut.state.isAuthenticated)
    }
}

// MARK: - ObservableSessionManager Tests (iOS 17+ / macOS 14+)

@available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
private typealias ObservableSUT = ObservableSessionManager<MockIdentityProvider, InMemoryCredentialStore<BearerToken>>

@available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
final class ObservableSessionManagerTests: XCTestCase {

    private func validCredential() -> EmailPasswordCredential {
        EmailPasswordCredential(email: "test@example.com", password: "password123")
    }

    @MainActor
    private func makeSUT(
        failSignIn:    Bool         = false,
        failRefresh:   Bool         = false,
        tokenLifetime: TimeInterval = 3600
    ) -> ObservableSUT {
        ObservableSUT(
            provider: MockIdentityProvider(
                simulatedLatency: .zero,
                shouldFailSignIn:  failSignIn,
                shouldFailRefresh: failRefresh,
                tokenLifetime:     tokenLifetime
            ),
            store: InMemoryCredentialStore<BearerToken>()
        )
    }

    // MARK: - Initial State

    @MainActor
    func test_observable_initialState_isRestoringSession() {
        let sut = makeSUT()
        XCTAssertEqual(sut.state, .loading(.restoringSession))
    }

    // MARK: - Sign In

    @MainActor
    func test_observable_signIn_transitionsToSignedIn() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertNotNil(sut.state.currentUser)
    }

    @MainActor
    func test_observable_signIn_failure_transitionsToFailed() async {
        let sut = makeSUT(failSignIn: true)
        await sut.signIn(with: validCredential())
        XCTAssertEqual(sut.state, .failed(.invalidCredentials))
    }

    // MARK: - Sign Out

    @MainActor
    func test_observable_signOut_transitionsToSignedOut() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        await sut.signOut()
        XCTAssertEqual(sut.state, .signedOut)
    }

    // MARK: - Token

    @MainActor
    func test_observable_currentValidToken_returnsBearerToken() async throws {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        let token = try await sut.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
    }

    @MainActor
    func test_observable_expiredToken_silentlyRefreshed() async throws {
        let sut = makeSUT(tokenLifetime: -1)
        await sut.signIn(with: validCredential())
        let token = try await sut.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
    }

    @MainActor
    func test_observable_refreshFails_transitionsToExpired() async {
        let sut = makeSUT(failRefresh: true, tokenLifetime: -1)
        await sut.signIn(with: validCredential())
        do {
            _ = try await sut.currentValidToken()
            XCTFail("Expected tokenRefreshFailed")
        } catch {
            XCTAssertEqual(sut.state, .expired)
        }
    }

    // MARK: - Configuration

    @MainActor
    func test_observable_customConfiguration() {
        let config = SessionManagerConfiguration(proactiveRefreshBuffer: 120, operationTimeout: 10)
        let sut = ObservableSUT(
            provider: MockIdentityProvider(simulatedLatency: .zero),
            store: InMemoryCredentialStore<BearerToken>(),
            configuration: config
        )
        XCTAssertEqual(sut.configuration.proactiveRefreshBuffer, 120)
        XCTAssertEqual(sut.configuration.operationTimeout, 10)
    }

    // MARK: - Update User

    @MainActor
    func test_observable_updateUser_reflectsInState() async {
        let sut = makeSUT()
        await sut.signIn(with: validCredential())
        sut.updateUser(SessionUser(id: "mock-001", displayName: "Updated", email: "new@b.com"))
        XCTAssertEqual(sut.state.currentUser?.displayName, "Updated")
    }

    // MARK: - AnyTokenProvider bridge

    @MainActor
    func test_anyTokenProvider_fromObservable() async throws {
        let manager = makeSUT()
        await manager.signIn(with: validCredential())

        let anyProvider = AnyTokenProvider(manager)
        let raw = try await anyProvider.currentRawToken()
        XCTAssertNotNil(raw)
        XCTAssertTrue(raw!.hasPrefix("mock-access-"))
    }
}
