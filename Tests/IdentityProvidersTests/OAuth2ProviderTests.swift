// MARK: - OAuth2ProviderTests.swift

import XCTest
@testable import IdentityProviders
import SessionManager

// MARK: - Helpers

/// Actor-based response sequence — safe to capture in a @Sendable SMNetworkHandler.
private actor ResponseSequence {
    private let responses: [(Data, Int)]
    private(set) var callCount = 0

    init(_ responses: [(Data, Int)]) {
        self.responses = responses
    }

    func next(for url: URL) throws -> (Data, URLResponse) {
        guard callCount < responses.count else {
            throw SessionError.providerError("Unexpected request \(callCount + 1) — only \(responses.count) response(s) stubbed")
        }
        defer { callCount += 1 }
        let (data, status) = responses[callCount]
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
        return (data, response)
    }
}

private func makeHandler(_ responses: (Data, Int)...) -> (SMNetworkHandler, ResponseSequence) {
    let seq = ResponseSequence(responses)
    let handler: SMNetworkHandler = { request in
        try await seq.next(for: request.url!)
    }
    return (handler, seq)
}

// MARK: - Fixture JSON

private func tokenJSON(
    accessToken:  String = "access-tok",
    refreshToken: String = "refresh-tok",
    expiresIn:    Int    = 3600
) -> Data {
    """
    {
        "access_token":  "\(accessToken)",
        "refresh_token": "\(refreshToken)",
        "token_type":    "Bearer",
        "expires_in":    \(expiresIn)
    }
    """.data(using: .utf8)!
}

private func userInfoJSON(
    sub:   String = "user-123",
    name:  String = "Test User",
    email: String = "test@example.com"
) -> Data {
    """
    { "sub": "\(sub)", "name": "\(name)", "email": "\(email)" }
    """.data(using: .utf8)!
}

// MARK: - Configuration helpers

private func makeConfig(
    withUserInfo:              Bool   = true,
    withRevocation:            Bool   = true,
    withAuthorizationEndpoint: Bool   = false,
    redirectURI:               String = "",
    additionalScopes:          [String] = []
) -> OAuth2Configuration {
    OAuth2Configuration(
        clientID:              "test-client",
        authorizationEndpoint: withAuthorizationEndpoint ? URL(string: "https://auth.example.com/authorize")! : nil,
        tokenEndpoint:         URL(string: "https://auth.example.com/token")!,
        revocationEndpoint:    withRevocation ? URL(string: "https://auth.example.com/revoke")! : nil,
        userInfoEndpoint:      withUserInfo   ? URL(string: "https://auth.example.com/userinfo")! : nil,
        redirectURI:           redirectURI,
        additionalScopes:      additionalScopes
    )
}

private func makeToken(refreshToken: String? = "refresh-tok") -> BearerToken {
    BearerToken(accessToken: "access-tok", refreshToken: refreshToken, expiresAt: nil)
}

private let validCredential = OAuthCredential(
    provider: "test",
    idToken:  "auth-code",
    nonce:    "code-verifier"
)

// MARK: - Tests

final class OAuth2ProviderTests: XCTestCase {

    // MARK: - signIn

    func test_signIn_exchangesCodeAndFetchesUser() async throws {
        let (handler, seq) = makeHandler(
            (tokenJSON(), 200),
            (userInfoJSON(), 200)
        )
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        let result = try await provider.signIn(with: validCredential)

        XCTAssertEqual(result.token.accessToken, "access-tok")
        XCTAssertEqual(result.token.refreshToken, "refresh-tok")
        XCTAssertEqual(result.user.id, "user-123")
        XCTAssertEqual(result.user.displayName, "Test User")
        XCTAssertEqual(result.user.email, "test@example.com")
        let calls = await seq.callCount
        XCTAssertEqual(calls, 2) // token exchange + userinfo
    }

    func test_signIn_missingNonce_throwsInvalidCredentials() async {
        let (handler, _) = makeHandler()
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)
        let credentialWithoutNonce = OAuthCredential(provider: "test", idToken: "code")

        do {
            _ = try await provider.signIn(with: credentialWithoutNonce)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    func test_signIn_server401_throwsInvalidCredentials() async {
        let (handler, _) = makeHandler((Data(), 401))
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.signIn(with: validCredential)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    func test_signIn_serverNon2xx_throwsProviderError() async {
        let (handler, _) = makeHandler((Data(), 500))
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.signIn(with: validCredential)
            XCTFail("Expected providerError")
        } catch SessionError.providerError { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    func test_signIn_malformedJSON_throwsProviderError() async {
        let (handler, _) = makeHandler(("not json".data(using: .utf8)!, 200))
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.signIn(with: validCredential)
            XCTFail("Expected providerError")
        } catch SessionError.providerError { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    // MARK: - refreshToken

    func test_refreshToken_withCachedUser_skipsUserInfoFetch() async throws {
        // Only one response stubbed — if userinfo were fetched, the second call would throw.
        let (handler, seq) = makeHandler((tokenJSON(accessToken: "new-access"), 200))
        let provider  = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)
        let cached    = SessionUser(id: "user-123", displayName: "Cached User")

        let result = try await provider.refreshToken(makeToken(), currentUser: cached)

        XCTAssertEqual(result.token.accessToken, "new-access")
        XCTAssertEqual(result.user.displayName, "Cached User") // unchanged
        let calls = await seq.callCount
        XCTAssertEqual(calls, 1) // token endpoint only
    }

    func test_refreshToken_withoutCachedUser_fetchesUserInfo() async throws {
        let (handler, seq) = makeHandler(
            (tokenJSON(accessToken: "new-access"), 200),
            (userInfoJSON(name: "Fresh User"), 200)
        )
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        let result = try await provider.refreshToken(makeToken(), currentUser: nil)

        XCTAssertEqual(result.token.accessToken, "new-access")
        XCTAssertEqual(result.user.displayName, "Fresh User")
        let calls = await seq.callCount
        XCTAssertEqual(calls, 2) // token + userinfo
    }

    func test_refreshToken_missingRefreshToken_throwsTokenRefreshFailed() async {
        let (handler, _) = makeHandler()
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.refreshToken(makeToken(refreshToken: nil), currentUser: nil)
            XCTFail("Expected tokenRefreshFailed")
        } catch SessionError.tokenRefreshFailed { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    // MARK: - signOut

    func test_signOut_callsRevocationEndpoint() async throws {
        let (handler, seq) = makeHandler((Data(), 200))
        let provider = OAuth2Provider(configuration: makeConfig(withRevocation: true), networkHandler: handler)

        try await provider.signOut(token: makeToken())

        let calls = await seq.callCount
        XCTAssertEqual(calls, 1)
    }

    func test_signOut_noRevocationEndpoint_isNoOp() async throws {
        let (handler, seq) = makeHandler() // zero responses — any call would throw
        let provider = OAuth2Provider(configuration: makeConfig(withRevocation: false), networkHandler: handler)

        try await provider.signOut(token: makeToken()) // must not throw

        let calls = await seq.callCount
        XCTAssertEqual(calls, 0)
    }

    // MARK: - authorizationRequest

    func test_authorizationRequest_noEndpoint_throwsProviderError() async {
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: { _ in fatalError() })
        do {
            _ = try await provider.authorizationRequest()
            XCTFail("Expected providerError")
        } catch SessionError.providerError { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    func test_authorizationRequest_containsRequiredPKCEParams() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: { _ in fatalError() }
        )
        let url   = try await provider.authorizationRequest(state: "test-state")
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!

        func value(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }

        XCTAssertEqual(value("response_type"),         "code")
        XCTAssertEqual(value("client_id"),             "test-client")
        XCTAssertEqual(value("code_challenge_method"), "S256")
        XCTAssertEqual(value("state"),                 "test-state")
        XCTAssertNotNil(value("code_challenge"))
    }

    func test_authorizationRequest_codeChallenge_isBase64URLWithoutPadding() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: { _ in fatalError() }
        )
        let url       = try await provider.authorizationRequest()
        let items     = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!
        let challenge = items.first(where: { $0.name == "code_challenge" })!.value!

        XCTAssertFalse(challenge.isEmpty)
        XCTAssertFalse(challenge.contains("="), "base64url must have no padding")
        XCTAssertFalse(challenge.contains("+"), "base64url must use - not +")
        XCTAssertFalse(challenge.contains("/"), "base64url must use _ not /")
    }

    func test_authorizationRequest_includesRedirectURI_whenConfigured() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true, redirectURI: "myapp://callback"),
            networkHandler: { _ in fatalError() }
        )
        let url   = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!
        XCTAssertEqual(items.first(where: { $0.name == "redirect_uri" })?.value, "myapp://callback")
    }

    func test_authorizationRequest_omitsRedirectURI_whenEmpty() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: { _ in fatalError() }
        )
        let url   = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!
        XCTAssertNil(items.first(where: { $0.name == "redirect_uri" }))
    }

    func test_authorizationRequest_includesScopes_whenConfigured() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true, additionalScopes: ["openid", "profile", "email"]),
            networkHandler: { _ in fatalError() }
        )
        let url   = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!
        XCTAssertEqual(items.first(where: { $0.name == "scope" })?.value, "openid profile email")
    }

    func test_authorizationRequest_consecutiveCalls_produceDifferentChallenges() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: { _ in fatalError() }
        )
        let url1 = try await provider.authorizationRequest()
        let url2 = try await provider.authorizationRequest()

        func challenge(_ url: URL) -> String? {
            URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "code_challenge" })?.value
        }
        func state(_ url: URL) -> String? {
            URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "state" })?.value
        }

        XCTAssertNotEqual(challenge(url1), challenge(url2))
        XCTAssertNotEqual(state(url1),     state(url2))
    }

    // MARK: - authorizationRequest — configurable parameter names

    func test_authorizationRequest_usesCustomChallengeParameterNames() async throws {
        let config = OAuth2Configuration(
            clientID:                         "test-client",
            authorizationEndpoint:            URL(string: "https://identity.enzona.net/oauth2/authorize")!,
            tokenEndpoint:                    URL(string: "https://identity.enzona.net/oauth2/token")!,
            codeChallengeParameterName:       "code_challange",
            codeChallengeMethodParameterName: "code_challange_method"
        )
        let provider = OAuth2Provider(configuration: config, networkHandler: { _ in fatalError() })
        let url      = try await provider.authorizationRequest()
        let items    = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!

        func value(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }

        XCTAssertNotNil(value("code_challange"),        "Typo param name must be used")
        XCTAssertEqual(value("code_challange_method"), "S256")
        XCTAssertNil(value("code_challenge"),           "Standard param name must not appear")
        XCTAssertNil(value("code_challenge_method"),    "Standard param name must not appear")
    }

    func test_authorizationRequest_defaultsToRFCParameterNames() async throws {
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: { _ in fatalError() }
        )
        let url   = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!

        func value(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }

        XCTAssertNotNil(value("code_challenge"))
        XCTAssertEqual(value("code_challenge_method"), "S256")
    }

    // MARK: - signIn — state validation (inside protocol conformance)

    func test_signIn_stateMismatch_throwsBeforeNetworkCall() async {
        // authorizationRequest stores "expected-state"; signIn receives "wrong-state".
        // Must throw before making any network call — zero responses stubbed.
        let (handler, seq) = makeHandler()
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: handler
        )
        _ = try? await provider.authorizationRequest(state: "expected-state")

        let credential = OAuthCredential(provider: "test", idToken: "code", state: "wrong-state")
        do {
            _ = try await provider.signIn(with: credential)
            XCTFail("Expected providerError")
        } catch SessionError.providerError(let msg) {
            XCTAssertTrue(msg.contains("State mismatch"))
        } catch { XCTFail("Wrong error: \(error)") }

        let calls = await seq.callCount
        XCTAssertEqual(calls, 0, "Network must not be reached on state mismatch")
    }

    func test_signIn_missingCallbackState_skipsValidation() async throws {
        // enzona.net doesn't echo state — credential.state is nil, validation is skipped.
        let (handler, _) = makeHandler(
            (tokenJSON(), 200),
            (userInfoJSON(), 200)
        )
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: handler
        )
        _ = try? await provider.authorizationRequest(state: "generated-state")

        let credential = OAuthCredential(provider: "test", idToken: "code")
        let result = try await provider.signIn(with: credential)
        XCTAssertEqual(result.token.accessToken, "access-tok")
    }

    func test_signIn_matchingState_succeedsAndExchangesCode() async throws {
        let (handler, _) = makeHandler(
            (tokenJSON(), 200),
            (userInfoJSON(), 200)
        )
        let provider = OAuth2Provider(
            configuration: makeConfig(withAuthorizationEndpoint: true),
            networkHandler: handler
        )
        _ = try? await provider.authorizationRequest(state: "my-state")

        let credential = OAuthCredential(provider: "test", idToken: "code", state: "my-state")
        let result = try await provider.signIn(with: credential)
        XCTAssertEqual(result.token.accessToken, "access-tok")
        XCTAssertEqual(result.user.id, "user-123")
    }

    // MARK: - OAuth2 error response parsing

    func test_refreshToken_invalidGrant_throwsInvalidCredentials() async {
        // HTTP 400 + {"error":"invalid_grant"} must be permanent so the engine
        // clears the store and transitions to .expired rather than retrying.
        let body = #"{"error":"invalid_grant","error_description":"Refresh token has been revoked"}"#
        let (handler, _) = makeHandler((body.data(using: .utf8)!, 400))
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.refreshToken(makeToken(), currentUser: nil)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials { /* ✅ permanent */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    func test_refreshToken_invalidClient_throwsInvalidCredentials() async {
        let body = #"{"error":"invalid_client"}"#
        let (handler, _) = makeHandler((body.data(using: .utf8)!, 400))
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.refreshToken(makeToken(), currentUser: nil)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    func test_refreshToken_serverError_throwsProviderError() async {
        // Transient server errors must not be treated as permanent.
        let body = #"{"error":"server_error","error_description":"Internal error"}"#
        let (handler, _) = makeHandler((body.data(using: .utf8)!, 503))
        let provider = OAuth2Provider(configuration: makeConfig(), networkHandler: handler)

        do {
            _ = try await provider.refreshToken(makeToken(), currentUser: nil)
            XCTFail("Expected providerError")
        } catch SessionError.providerError { /* ✅ transient */ }
          catch { XCTFail("Wrong error: \(error)") }
    }

    // MARK: - userInfoEndpoint

    func test_signIn_missingUserInfoEndpoint_throwsProviderError() async {
        // Token exchange succeeds but no userInfoEndpoint configured.
        let (handler, _) = makeHandler((tokenJSON(), 200))
        let provider = OAuth2Provider(configuration: makeConfig(withUserInfo: false), networkHandler: handler)

        do {
            _ = try await provider.signIn(with: validCredential)
            XCTFail("Expected providerError")
        } catch SessionError.providerError { /* ✅ */ }
          catch { XCTFail("Wrong error: \(error)") }
    }
}
