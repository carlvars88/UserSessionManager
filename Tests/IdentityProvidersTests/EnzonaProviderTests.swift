// MARK: - EnzonaProviderTests.swift

import XCTest
@testable import IdentityProviders
import SessionManager

// MARK: - Helpers (shared with OAuth2ProviderTests pattern)

private actor EnzonaResponseSequence {
    private let responses: [(Data, Int)]
    private(set) var callCount = 0

    init(_ responses: [(Data, Int)]) { self.responses = responses }

    func next(for url: URL) throws -> (Data, URLResponse) {
        guard callCount < responses.count else {
            throw SessionError.providerError(
                "Unexpected request \(callCount + 1) — only \(responses.count) response(s) stubbed"
            )
        }
        defer { callCount += 1 }
        let (data, status) = responses[callCount]
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
        return (data, response)
    }
}

private func makeHandler(_ responses: (Data, Int)...) -> (SMNetworkHandler, EnzonaResponseSequence) {
    let seq = EnzonaResponseSequence(responses)
    let handler: SMNetworkHandler = { request in try await seq.next(for: request.url!) }
    return (handler, seq)
}

// MARK: - Fixture JSON

private func tokenJSON(
    accessToken:  String = "17ef2789-0b67-3c52-b32c-4d1f91b562f8",
    refreshToken: String = "59faca5b-430f-3060-8e23-93c44d6e4f24",
    expiresIn:    Int    = 6673
) -> Data {
    """
    {
      "access_token":  "\(accessToken)",
      "refresh_token": "\(refreshToken)",
      "token_type":    "Bearer",
      "expires_in":    \(expiresIn),
      "scope":         "openid",
      "id_token":      "eyJhbGciOiJSUzI1NiJ9.stub.sig"
    }
    """.data(using: .utf8)!
}

private func userInfoJSON(
    sub:        String = "cpujol542",
    givenName:  String = "Carlos",
    familyName: String = "Pujol Vargas",
    email:      String = "pujolvargasas@gmail.com"
) -> Data {
    """
    {
      "sub":         "\(sub)",
      "given_name":  "\(givenName)",
      "family_name": "\(familyName)",
      "email":       "\(email)"
    }
    """.data(using: .utf8)!
}

private func errorJSON(_ code: String, description: String? = nil) -> Data {
    if let description {
        return """
        {"error": "\(code)", "error_description": "\(description)"}
        """.data(using: .utf8)!
    }
    return """
    {"error": "\(code)"}
    """.data(using: .utf8)!
}

private actor BodyCapture {
    private(set) var value: String?
    func set(_ body: Data?) { value = body.flatMap { String(data: $0, encoding: .utf8) } }
    func setIfNil(_ body: Data?) { if value == nil { set(body) } }
}

// MARK: - Provider factory

private func makeProvider(handler: @escaping SMNetworkHandler) -> EnzonaProvider {
    EnzonaProvider(
        configuration:  EnzonaConfiguration(
            clientID:    "ofr3Wz9nnfZaFd18OewdZYvuTaEa",
            redirectURI: "http://apk-callback"
        ),
        networkHandler: handler
    )
}

private func seedCookie(_ value: String) {
    let expiry = Date().addingTimeInterval(365 * 24 * 3600)
    let props: [HTTPCookiePropertyKey: Any] = [
        .name: "deviceAuth", .value: value,
        .domain: "identity.enzona.net", .path: "/",
        .secure: "TRUE", .expires: expiry
    ]
    if let c = HTTPCookie(properties: props) { HTTPCookieStorage.shared.setCookie(c) }
}

private func clearCookie() {
    HTTPCookieStorage.shared.cookies?
        .filter { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
        .forEach { HTTPCookieStorage.shared.deleteCookie($0) }
}

// MARK: - EnzonaProviderTests

final class EnzonaProviderTests: XCTestCase {

    // MARK: authorizationRequest — URL shape

    func test_authorizationRequest_containsRequiredParams() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        let url = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let param = { (name: String) in items.first(where: { $0.name == name })?.value }

        XCTAssertEqual(param("response_type"), "code")
        XCTAssertEqual(param("client_id"), "ofr3Wz9nnfZaFd18OewdZYvuTaEa")
        XCTAssertEqual(param("redirect_uri"), "http://apk-callback")
        XCTAssertEqual(param("scope"), "openid")
    }

    func test_authorizationRequest_usesMisspelledPKCEParams() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        let url = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let names = items.map(\.name)

        // enzona uses "code_challange" (typo), not "code_challenge"
        XCTAssertTrue(names.contains("code_challange"),       "expected misspelled code_challange")
        XCTAssertTrue(names.contains("code_challange_method"), "expected misspelled code_challange_method")
        XCTAssertFalse(names.contains("code_challenge"),       "should NOT contain correctly spelled code_challenge")
        XCTAssertFalse(names.contains("code_challenge_method"))
    }

    func test_authorizationRequest_challengeMethodIsS256() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        let url = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let method = items.first(where: { $0.name == "code_challange_method" })?.value
        XCTAssertEqual(method, "S256")
    }

    func test_authorizationRequest_noStateParam() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        let url = try await provider.authorizationRequest()
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []

        // enzona doesn't use state
        XCTAssertFalse(items.map(\.name).contains("state"))
    }

    func test_authorizationRequest_challengeIsDifferentEachCall() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        let url1 = try await provider.authorizationRequest()
        let url2 = try await provider.authorizationRequest()

        let challenge = { (url: URL) -> String? in
            URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "code_challange" })?.value
        }
        XCTAssertNotEqual(challenge(url1), challenge(url2), "Each call must generate a fresh PKCE verifier")
    }

    // MARK: deviceAuth cookie injection

    func test_authorizationRequest_injectsCookieFromMetadata() async throws {
        // metadata["deviceAuthCookie"] is the source of truth for device trust.
        // Passing a user that carries the value causes it to be written into HTTPCookieStorage
        // so a non-ephemeral webview session picks it up automatically.
        clearCookie()
        defer { clearCookie() }

        let provider = makeProvider(handler: makeHandler().0)
        let trustedUser = SessionUser(id: "u1", displayName: "Test", email: nil,
                                      metadata: ["deviceAuthCookie": "abc123"])
        _ = try await provider.authorizationRequest(currentUser: trustedUser)

        let injected = HTTPCookieStorage.shared.cookies?
            .first { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
        XCTAssertNotNil(injected, "deviceAuth cookie should be injected into HTTPCookieStorage from metadata")
        XCTAssertEqual(injected?.value, "abc123")
    }

    func test_authorizationRequest_noCookieInjectedWhenStorageEmpty() async throws {
        clearCookie()

        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()

        let injected = HTTPCookieStorage.shared.cookies?
            .first { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
        XCTAssertNil(injected, "No cookie should be injected when none is stored")
    }

    func test_signIn_storesCookieInUserMetadata() async throws {
        clearCookie()
        defer { clearCookie() }

        let (handler, _) = makeHandler((tokenJSON(), 200), (userInfoJSON(), 200))
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()
        // Simulate the server having set deviceAuth in the webview session
        // (this happens AFTER authorizationRequest opens the webview, not before).
        seedCookie("server-set-cookie")
        let result = try await provider.signIn(with: OAuthCredential(provider: "enzona", idToken: "code"))

        XCTAssertEqual(result.user.metadata["deviceAuthCookie"], "server-set-cookie",
                       "deviceAuth should be persisted in SessionUser.metadata after signIn")
    }

    func test_refreshToken_carriesCookieForwardInMetadata() async throws {
        let (handler, _) = makeHandler((tokenJSON(accessToken: "new-at", refreshToken: "new-rt"), 200))
        let provider = makeProvider(handler: handler)

        let oldToken = BearerToken(accessToken: "old", refreshToken: "old-rt", expiresAt: nil)
        // currentUser already has the cookie in metadata (as KeychainCredentialStore provides)
        let oldUser = SessionUser(id: "cpujol542", displayName: "Carlos", email: nil,
                                  avatarURL: nil, metadata: ["deviceAuthCookie": "persisted-cookie"])
        let result = try await provider.refreshToken(oldToken, currentUser: oldUser)

        // refreshToken returns currentUser unchanged — metadata is preserved as-is.
        // deviceAuth is set once at sign-in; refresh never touches HTTPCookieStorage.
        XCTAssertEqual(result.user.metadata["deviceAuthCookie"], "persisted-cookie",
                       "deviceAuthCookie must be carried forward from currentUser metadata")
    }

    // MARK: signIn

    func test_signIn_exchangesCodeForToken() async throws {
        let (handler, seq) = makeHandler(
            (tokenJSON(), 200),
            (userInfoJSON(), 200)
        )
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()
        let credential = OAuthCredential(provider: "enzona", idToken: "auth-code-xyz")
        let result = try await provider.signIn(with: credential)

        XCTAssertEqual(result.token.accessToken,  "17ef2789-0b67-3c52-b32c-4d1f91b562f8")
        XCTAssertEqual(result.token.refreshToken, "59faca5b-430f-3060-8e23-93c44d6e4f24")
        XCTAssertEqual(result.user.id,            "cpujol542")
        XCTAssertEqual(result.user.email,         "pujolvargasas@gmail.com")
        let calls = await seq.callCount
        XCTAssertEqual(calls, 2) // token + userinfo
    }

    func test_signIn_tokenRequestIncludesCodeVerifier() async throws {
        let capture = BodyCapture()
        let provider = EnzonaProvider(
            configuration:  EnzonaConfiguration(
                clientID:    "ofr3Wz9nnfZaFd18OewdZYvuTaEa",
                redirectURI: "http://apk-callback"
            ),
            networkHandler: { request in
                await capture.setIfNil(request.httpBody)
                let url = request.url!
                if url.path.contains("userinfo") {
                    return (userInfoJSON(), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!)
                }
                return (tokenJSON(), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
        )
        _ = try await provider.authorizationRequest()
        let credential = OAuthCredential(provider: "enzona", idToken: "my-code")
        _ = try await provider.signIn(with: credential)

        let body = await capture.value
        XCTAssertNotNil(body)
        XCTAssertTrue(body!.contains("code_verifier="), "Token request must include code_verifier")
        XCTAssertTrue(body!.contains("grant_type=authorization_code"))
        XCTAssertTrue(body!.contains("code=my-code"))
    }

    func test_signIn_withoutPriorAuthorizationRequest_throwsWhenNoNonce() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        // No authorizationRequest() call, no nonce in credential
        let credential = OAuthCredential(provider: "enzona", idToken: "code", nonce: nil)
        do {
            _ = try await provider.signIn(with: credential)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials {
            // correct
        }
    }

    func test_signIn_withManualNonce_succeedsWithoutAuthorizationRequest() async throws {
        let (handler, _) = makeHandler((tokenJSON(), 200), (userInfoJSON(), 200))
        let provider = makeProvider(handler: handler)
        // Skip authorizationRequest, supply nonce manually
        let credential = OAuthCredential(provider: "enzona", idToken: "code", nonce: "manual-verifier")
        let result = try await provider.signIn(with: credential)
        XCTAssertEqual(result.user.id, "cpujol542")
    }

    func test_signIn_userDisplayNameFromGivenAndFamilyName() async throws {
        let (handler, _) = makeHandler(
            (tokenJSON(), 200),
            (userInfoJSON(givenName: "Carlos", familyName: "Pujol Vargas"), 200)
        )
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()
        let result = try await provider.signIn(with: OAuthCredential(provider: "enzona", idToken: "c"))
        XCTAssertEqual(result.user.displayName, "Carlos Pujol Vargas")
    }

    // MARK: Refresh Token

    func test_refreshToken_sendsRefreshGrant() async throws {
        let capture = BodyCapture()
        let provider = EnzonaProvider(
            configuration:  EnzonaConfiguration(
                clientID:    "ofr3Wz9nnfZaFd18OewdZYvuTaEa",
                redirectURI: "http://apk-callback"
            ),
            networkHandler: { request in
                await capture.set(request.httpBody)
                let url = request.url!
                return (tokenJSON(accessToken: "new-access", refreshToken: "new-refresh"),
                        HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
        )
        let oldToken = BearerToken(accessToken: "old", refreshToken: "old-rt", expiresAt: nil)
        let oldUser  = SessionUser(id: "cpujol542", displayName: "Carlos", email: nil, avatarURL: nil)
        let result   = try await provider.refreshToken(oldToken, currentUser: oldUser)

        let body = await capture.value
        XCTAssertEqual(result.token.accessToken, "new-access")
        XCTAssertTrue(body!.contains("grant_type=refresh_token"))
        XCTAssertTrue(body!.contains("refresh_token=old-rt"))
    }

    func test_refreshToken_withoutRefreshToken_throwsTokenRefreshFailed() async throws {
        let (handler, _) = makeHandler()
        let provider = makeProvider(handler: handler)
        let token = BearerToken(accessToken: "access", refreshToken: nil, expiresAt: nil)
        do {
            _ = try await provider.refreshToken(token, currentUser: nil)
            XCTFail("Expected tokenRefreshFailed")
        } catch SessionError.tokenRefreshFailed {
            // correct
        }
    }

    // MARK: Sign Out

    func test_signOut_sendsRevocationRequest() async throws {
        let capture = BodyCapture()
        let provider = EnzonaProvider(
            configuration: EnzonaConfiguration(
                clientID:    "ofr3Wz9nnfZaFd18OewdZYvuTaEa",
                redirectURI: "http://apk-callback"
            ),
            networkHandler: { request in
                await capture.set(request.httpBody)
                let url = request.url!
                return (Data(), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
        )
        let token = BearerToken(accessToken: "at", refreshToken: "rt", expiresAt: nil)
        try await provider.signOut(token: token)

        let body = await capture.value
        XCTAssertNotNil(body)
        XCTAssertTrue(body!.contains("token=rt"))
        XCTAssertTrue(body!.contains("token_type_hint=refresh_token"))
    }

    // MARK: Device trust revocation

    func test_authorizationRequest_withoutDeviceCookieInMetadata_removesCookieFromStorage() async throws {
        clearCookie()
        seedCookie("trust-cookie")

        let provider = makeProvider(handler: makeHandler((tokenJSON(), 200), (userInfoJSON(), 200)).0)

        // A user with no deviceAuthCookie in metadata signals device is untrusted.
        let userWithoutDeviceTrust = SessionUser(id: "u1", displayName: "Test", email: nil)
        _ = try await provider.authorizationRequest(currentUser: userWithoutDeviceTrust)

        // HTTPCookieStorage must be cleared
        let cookie = HTTPCookieStorage.shared.cookies?
            .first { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
        XCTAssertNil(cookie, "deviceAuth must be removed from HTTPCookieStorage when metadata has no deviceAuthCookie")

        // Subsequent authorizationRequest without metadata must not re-inject the cookie
        _ = try await provider.authorizationRequest(currentUser: userWithoutDeviceTrust)
        let reinjected = HTTPCookieStorage.shared.cookies?
            .first { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
        XCTAssertNil(reinjected, "authorizationRequest must not inject cookie when metadata has no deviceAuthCookie")
    }

    func test_removingMetadataKeys_stripsSpecifiedKeys() {
        let user = SessionUser(id: "u1", displayName: "Carlos",
                               metadata: ["deviceAuthCookie": "abc", "other": "keep"])
        let updated = user.removing(metadataKeys: ["deviceAuthCookie"])
        XCTAssertNil(updated.metadata["deviceAuthCookie"])
        XCTAssertEqual(updated.metadata["other"], "keep")
    }

    // MARK: Error classification

    func test_invalidGrant_mapsToInvalidCredentials() async throws {
        let (handler, _) = makeHandler((errorJSON("invalid_grant"), 400), (userInfoJSON(), 200))
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()
        let credential = OAuthCredential(provider: "enzona", idToken: "expired-code")
        do {
            _ = try await provider.signIn(with: credential)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials {
            // correct — permanent failure
        }
    }

    func test_serverError_mapsToProviderError() async throws {
        let (handler, _) = makeHandler(
            (errorJSON("server_error", description: "Internal error"), 500),
            (userInfoJSON(), 200)
        )
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()
        let credential = OAuthCredential(provider: "enzona", idToken: "code")
        do {
            _ = try await provider.signIn(with: credential)
            XCTFail("Expected providerError")
        } catch SessionError.providerError(let msg) {
            XCTAssertTrue(msg.contains("Internal error"))
        }
    }

    func test_http401_mapsToInvalidCredentials() async throws {
        let (handler, _) = makeHandler((Data(), 401))
        let provider = makeProvider(handler: handler)
        _ = try await provider.authorizationRequest()
        let credential = OAuthCredential(provider: "enzona", idToken: "code")
        do {
            _ = try await provider.signIn(with: credential)
            XCTFail("Expected invalidCredentials")
        } catch SessionError.invalidCredentials {
            // correct
        }
    }
}
