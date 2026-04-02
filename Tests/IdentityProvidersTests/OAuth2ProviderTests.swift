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

private func makeConfig(withUserInfo: Bool = true, withRevocation: Bool = true) -> OAuth2Configuration {
    OAuth2Configuration(
        clientID:           "test-client",
        tokenEndpoint:      URL(string: "https://auth.example.com/token")!,
        revocationEndpoint: withRevocation ? URL(string: "https://auth.example.com/revoke")! : nil,
        userInfoEndpoint:   withUserInfo   ? URL(string: "https://auth.example.com/userinfo")! : nil
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
