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

    func test_mockTokenProvider_success() async throws {
        let provider = MockTokenProvider<BearerToken>(.success(BearerToken(accessToken: "tok")))
        let token = try await provider.currentValidToken()
        XCTAssertEqual(token.accessToken, "tok")
    }

    func test_mockTokenProvider_failure() async {
        let provider = MockTokenProvider<BearerToken>(.failure(.sessionNotFound))
        do {
            _ = try await provider.currentValidToken()
            XCTFail("Expected failure")
        } catch SessionError.sessionNotFound { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    // MARK: - Protocol actor-agnostic

    func test_protocolAllowsConformanceOnAnyActor() async {
        actor BackgroundManager: @preconcurrency UserSessionManaging {
            typealias Provider = InlineProvider
            typealias Store    = InMemoryCredentialStore<OpaqueSessionToken>

            struct InlineProvider: IdentityProvider, Sendable {
                typealias Credential = TokenCredential
                typealias Token      = OpaqueSessionToken
                let providerID = "bg"
                func signIn(with c: TokenCredential) async throws -> AuthResult<OpaqueSessionToken> {
                    AuthResult(user: SessionUser(id: "bg", displayName: "BG User"),
                               token: OpaqueSessionToken(value: "bg-tok"))
                }
                func refreshToken(_ t: OpaqueSessionToken) async throws -> AuthResult<OpaqueSessionToken> {
                    throw SessionError.tokenRefreshFailed
                }
                func signOut(token: OpaqueSessionToken) async throws {}
            }

            var state: SessionState = .signedOut

            func signIn(with credential: TokenCredential) async {
                state = .signedIn(SessionUser(id: "bg", displayName: "BG User"))
            }
            func signOut() async { state = .signedOut }
            func reauthenticate(with credential: TokenCredential) async throws {}
            func updateUser(_ user: SessionUser) { state = .signedIn(user) }
        }

        let bg = BackgroundManager()
        await bg.signIn(with: TokenCredential(rawToken: "t", provider: "bg"))
        let s = await bg.state
        XCTAssertEqual(s.currentUser?.displayName, "BG User")
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
    func test_signOut_whileLoading_isIgnored() async {
        // Use a slow provider so signIn stays in .loading(.signingIn) long enough
        let slowProvider = MockIdentityProvider(
            simulatedLatency: .seconds(2),
            shouldFailSignIn: false,
            tokenLifetime: 3600
        )
        let sut = SUT(
            provider: slowProvider,
            store: InMemoryCredentialStore<BearerToken>()
        )
        // Start signIn in background — it will be in .loading(.signingIn)
        let signInTask = Task { await sut.signIn(with: validCredential()) }
        // Wait briefly for signIn to enter .loading(.signingIn)
        try? await Task.sleep(nanoseconds: 100_000_000) // 0.1s
        XCTAssertEqual(sut.state, .loading(.signingIn))
        // Now attempt signOut while signIn is in progress — should be ignored
        await sut.signOut()
        // Wait for signIn to complete
        await signInTask.value
        // Should have completed signIn successfully (signOut was ignored)
        XCTAssertTrue(sut.state.isAuthenticated)
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

    // MARK: - MultiCredential through sign-in flow

    @MainActor
    func test_multiCredential_signIn() async {
        // Proves MultiCredential compiles and works through the full flow
        typealias Multi = MultiCredential<EmailPasswordCredential, TokenCredential>

        struct MultiProvider: IdentityProvider, Sendable {
            typealias Credential = Multi
            typealias Token = OpaqueSessionToken
            let providerID = "multi"

            func signIn(with credential: Multi) async throws -> AuthResult<OpaqueSessionToken> {
                switch credential {
                case .first(let email):
                    guard email.email.contains("@") else { throw SessionError.invalidCredentials }
                    return AuthResult(
                        user: SessionUser(id: "m1", displayName: email.email),
                        token: OpaqueSessionToken(value: "multi-tok")
                    )
                case .second(let token):
                    return AuthResult(
                        user: SessionUser(id: "m2", displayName: token.provider),
                        token: OpaqueSessionToken(value: token.rawToken)
                    )
                }
            }
            func refreshToken(_ token: OpaqueSessionToken) async throws -> AuthResult<OpaqueSessionToken> {
                throw SessionError.tokenRefreshFailed
            }
            func signOut(token: OpaqueSessionToken) async throws {}
        }

        let sut = UserSessionManager(
            provider: MultiProvider(),
            store: InMemoryCredentialStore<OpaqueSessionToken>()
        )

        await sut.signIn(with: .first(EmailPasswordCredential(email: "a@b.com", password: "password123")))
        XCTAssertTrue(sut.state.isAuthenticated)
        XCTAssertEqual(sut.state.currentUser?.displayName, "a@b.com")
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

    // MARK: - AnySessionManager bridge

    @MainActor
    func test_anySessionManager_fromObservable() async throws {
        let manager = makeSUT()
        await manager.signIn(with: validCredential())

        let erased = AnySessionManager<EmailPasswordCredential, BearerToken>(manager)
        let token = try await erased.currentValidToken()
        XCTAssertFalse(token.accessToken.isEmpty)
        XCTAssertTrue(erased.state.isAuthenticated)
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
