// MARK: - EnzonaProvider.swift
//
// Custom IdentityProvider for enzona.net, which runs on WSO2 Identity Server
// (carbon.super tenant). Non-standard aspects handled here:
//
//   • PKCE parameters are misspelled: `code_challange` / `code_challange_method`
//   • No `state` parameter in the authorization URL (server ignores it)
//   • `deviceAuth` cookie must be present in the browser session to skip 2FA
//
// deviceAuth persistence
// ──────────────────────
// `SessionUser.metadata["deviceAuthCookie"]` is the single source of truth
// for device trust. It is persisted by `KeychainCredentialStore` under the
// user key, which `clearToken()` does NOT delete, so the value survives
// token expiry cycles.
//
// `HTTPCookieStorage.shared` is a write-only injection target: when
// `authorizationRequest(currentUser:)` is called it reads the metadata value
// and — if present — injects the cookie so the non-ephemeral webview session
// sends it automatically. If the value is absent (user removed device trust)
// any stale cookie is deleted from storage so it cannot sneak through.
//
// To revoke device trust from User Preferences:
//
//   if let user = session.currentUser {
//       await session.updateUser(user.removing(metadataKeys: ["deviceAuthCookie"]))
//   }
//   // HTTPCookieStorage is cleaned up automatically on the next authorizationRequest call.
//
// Usage:
//
//   let provider = EnzonaProvider(
//       clientID:       "ofr3Wz9nnfZaFd18OewdZYvuTaEa",
//       redirectURI:    "http://apk-callback",
//       networkHandler: URLSession.shared.data(for:)
//   )
//
//   let session = UserSessionManager(
//       provider: provider,
//       store:    KeychainCredentialStore<BearerToken>()
//   )
//
//   // 1. Build the authorization URL (generates PKCE internally).
//   //    Pass the current user so the provider can read deviceAuth from
//   //    metadata — the single source of truth for device trust.
//   let authURL = try await provider.authorizationRequest(currentUser: session.currentUser)
//
//   // 2. Open authURL in ASWebAuthenticationSession (non-ephemeral so the
//   //    injected cookie is sent). On callback, extract `code`:
//   //
//   //      let items = URLComponents(url: callbackURL,
//   //                               resolvingAgainstBaseURL: false)?.queryItems
//   //      let code  = items?.first(where: { $0.name == "code" })?.value ?? ""
//
//   // 3. Sign in. The provider reads the deviceAuth cookie the server set
//   //    during the flow and stores it in SessionUser.metadata automatically.
//   let credential = OAuthCredential(provider: "enzona", idToken: code)
//   await session.signIn(with: credential)

import CryptoKit
import Foundation
import SessionManager

// MARK: - Private response shapes

private struct EnzonaTokenResponse: Decodable {
    let access_token:  String
    let refresh_token: String?
    let token_type:    String?
    let expires_in:    Int?
    let scope:         String?
    let id_token:      String?
}

private struct EnzonaErrorResponse: Decodable {
    let error:             String
    let error_description: String?
}

private struct EnzonaUserInfoResponse: Decodable {
    let sub:                String?
    let name:               String?
    let given_name:         String?
    let family_name:        String?
    let preferred_username: String?
    let email:              String?
    let picture:            String?
}

// MARK: - EnzonaProvider

/// Identity provider for enzona.net (WSO2 Identity Server, carbon.super tenant).
///
/// Implements Authorization Code + PKCE, working around the server's
/// non-standard PKCE parameter names and injecting the `deviceAuth`
/// cookie that suppresses the 2FA prompt on trusted devices.
///
/// **Credential**: `OAuthCredential`
///   - `idToken`  → the authorization code from the callback URL
///   - `provider` → `"enzona"` (or any label you prefer)
///   - `state`, `nonce`, `accessToken` → leave `nil` (not used)
///
/// **Token**: `BearerToken`
///   - `accessToken`  → enzona access token (UUID format)
///   - `refreshToken` → enzona refresh token (UUID format)
///   - `expiresAt`    → computed from `expires_in`
///   - `scopes`       → granted scopes (e.g. `["openid"]`)
public actor EnzonaProvider: IdentityProvider {

    public typealias Credential = OAuthCredential
    public typealias Token      = BearerToken

    public nonisolated let providerID: String

    // MARK: Endpoints (WSO2 / enzona)

    private static let authorizationEndpoint = URL(string: "https://identity.enzona.net/oauth2/authorize")!
    private static let tokenEndpoint         = URL(string: "https://identity.enzona.net/oauth2/token")!
    private static let userInfoEndpoint      = URL(string: "https://identity.enzona.net/oauth2/userinfo")!
    private static let revocationEndpoint    = URL(string: "https://identity.enzona.net/oauth2/revoke")!

    // MARK: Stored state

    private let clientID:       String
    private let redirectURI:    String
    private let scopes:         [String]
    private let networkHandler: SMNetworkHandler

    // Pending PKCE verifier stored by authorizationRequest, consumed by signIn.
    private var pendingCodeVerifier: String?

    // MARK: Init

    /// Creates an `EnzonaProvider`.
    ///
    /// - Parameters:
    ///   - clientID: OAuth2 client identifier registered with enzona.
    ///   - redirectURI: Redirect URI registered with enzona (e.g. `"http://apk-callback"`).
    ///   - scopes: OAuth2 scopes to request. Defaults to `["openid"]`.
    ///   - providerID: Label used in log messages. Defaults to `"enzona"`.
    ///   - networkHandler: Closure used for token / userinfo / revocation network calls.
    ///     Pass `URLSession.shared.data(for:)`, a pinned session, or a test stub.
    public init(
        clientID:       String,
        redirectURI:    String,
        scopes:         [String]              = ["openid"],
        providerID:     String                = "enzona",
        networkHandler: @escaping SMNetworkHandler
    ) {
        self.clientID       = clientID
        self.redirectURI    = redirectURI
        self.scopes         = scopes
        self.providerID     = providerID
        self.networkHandler = networkHandler
    }

    // MARK: - Authorization Request (PKCE)

    /// Builds the enzona authorization URL to open in a browser or
    /// `ASWebAuthenticationSession`.
    ///
    /// - Parameter currentUser: The currently signed-in user, or `nil` when
    ///   called from the sign-in screen before a session exists. The provider
    ///   reads `currentUser.metadata["deviceAuthCookie"]` — the single source
    ///   of truth for device trust. If the value is present the cookie is
    ///   injected into `HTTPCookieStorage.shared` so a non-ephemeral webview
    ///   session sends it automatically. If the value is absent any stale
    ///   cookie is deleted from storage so it cannot bypass 2FA.
    /// - Generates a cryptographically random PKCE `code_verifier` and derives
    ///   the challenge via SHA-256 (S256), using enzona's misspelled parameter
    ///   names (`code_challange` / `code_challange_method`).
    /// - enzona does not echo a `state` parameter back in the callback URL,
    ///   so no state is added to the URL and none is validated in `signIn`.
    ///
    /// After the server redirects back, extract the `code` query item and pass
    /// it to `signIn(with:)` via `OAuthCredential.idToken`:
    ///
    /// ```swift
    /// let authURL = try await provider.authorizationRequest(currentUser: session.currentUser)
    /// // open authURL in ASWebAuthenticationSession (prefersEphemeralWebBrowserSession = false)
    /// // on callback:
    /// let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems
    /// let code  = items?.first(where: { $0.name == "code" })?.value ?? ""
    /// await session.signIn(with: OAuthCredential(provider: "enzona", idToken: code))
    /// ```
    public func authorizationRequest(currentUser: SessionUser? = nil) throws -> URL {
        // Metadata is the single source of truth for device trust.
        // HTTPCookieStorage is a write-only injection target — never a read source.
        if let cookieValue = currentUser?.metadata["deviceAuthCookie"] {
            injectCookieIntoStorageIfNeeded(cookieValue)
        } else {
            // No trust in metadata (first login, or user removed trust).
            // Delete any stale cookie so the server always prompts for 2FA.
            removeFromCookieStorage()
        }

        let codeVerifier  = Self.generateCodeVerifier()
        let codeChallenge = Self.codeChallenge(for: codeVerifier)
        pendingCodeVerifier = codeVerifier

        guard var components = URLComponents(url: Self.authorizationEndpoint, resolvingAgainstBaseURL: false) else {
            throw SessionError.providerError("Invalid authorizationEndpoint URL")
        }

        var items: [URLQueryItem] = [
            URLQueryItem(name: "response_type",       value: "code"),
            URLQueryItem(name: "client_id",           value: clientID),
            URLQueryItem(name: "code_challange",       value: codeChallenge),   // enzona typo
            URLQueryItem(name: "code_challange_method", value: "S256"),          // enzona typo
        ]
        if !redirectURI.isEmpty {
            items.append(URLQueryItem(name: "redirect_uri", value: redirectURI))
        }
        if !scopes.isEmpty {
            items.append(URLQueryItem(name: "scope", value: scopes.joined(separator: " ")))
        }
        components.queryItems = items

        guard let url = components.url else {
            throw SessionError.providerError("Failed to build authorization URL")
        }
        return url
    }

    // MARK: - Sign In (Authorization Code → Token Exchange)

    public func signIn(with credential: OAuthCredential) async throws -> AuthResult<BearerToken> {
        // Consume the PKCE verifier stored by authorizationRequest.
        // Fall back to credential.nonce for callers that manage PKCE manually.
        let codeVerifier    = pendingCodeVerifier ?? credential.nonce
        pendingCodeVerifier = nil

        guard let codeVerifier else {
            throw SessionError.invalidCredentials
        }

        // enzona does not echo state — no state validation needed.

        var params: [String: String] = [
            "grant_type":    "authorization_code",
            "code":          credential.idToken,
            "client_id":     clientID,
            "code_verifier": codeVerifier,
        ]
        if !redirectURI.isEmpty {
            params["redirect_uri"] = redirectURI
        }

        let response: EnzonaTokenResponse = try await decode(
            EnzonaTokenResponse.self,
            from: postRequest(Self.tokenEndpoint, form: params)
        )
        let token = mapToken(response)
        var user  = try await fetchUserInfo(accessToken: token.accessToken)

        // After a successful authorization flow the server may have set the
        // deviceAuth cookie in the webview session (HTTPCookieStorage).
        // Store it in the user metadata so it survives token expiry via
        // KeychainCredentialStore's split user key.
        if let cookie = HTTPCookieStorage.shared.cookies?
                .first(where: { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }) {
            // Replace the server-set cookie (possibly session-only) with a
            // persistent 1-year copy so it survives process restarts.
            removeFromCookieStorage()
            injectCookieIntoStorageIfNeeded(cookie.value)
            user = user.adding(metadata: ["deviceAuthCookie": cookie.value])
        }

        return AuthResult(user: user, token: token)
    }

    // MARK: - Refresh Token

    public func refreshToken(_ token: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> {
        guard let refreshToken = token.refreshToken else {
            throw SessionError.tokenRefreshFailed
        }

        let params: [String: String] = [
            "grant_type":    "refresh_token",
            "refresh_token": refreshToken,
            "client_id":     clientID,
        ]

        let response: EnzonaTokenResponse = try await decode(
            EnzonaTokenResponse.self,
            from: postRequest(Self.tokenEndpoint, form: params)
        )
        let newToken = mapToken(response)
        // currentUser already carries all metadata (including deviceAuthCookie)
        // from the Keychain user entry — return it unchanged so nothing is lost.
        // When nil (explicit refreshUser() call), fetch a fresh profile.
        let user = if let currentUser {
            currentUser
        } else {
            try await fetchUserInfo(accessToken: newToken.accessToken)
        }

        return AuthResult(user: user, token: newToken)
    }

    // MARK: - Sign Out (Token Revocation)

    public func signOut(token: BearerToken) async throws {
        let params: [String: String] = [
            "token":           token.refreshToken ?? token.accessToken,
            "client_id":       clientID,
            "token_type_hint": token.refreshToken != nil ? "refresh_token" : "access_token",
        ]
        try await send(postRequest(Self.revocationEndpoint, form: params))
        // Device trust is tied to the session — clear the cookie so the next
        // login always requires 2FA. The Keychain user entry (metadata) is
        // cleared by the session engine's store.clear() call.
        removeFromCookieStorage()
    }

    // MARK: - UserInfo

    private func fetchUserInfo(accessToken: String) async throws -> SessionUser {
        let response: EnzonaUserInfoResponse = try await decode(
            EnzonaUserInfoResponse.self,
            from: getRequest(Self.userInfoEndpoint, bearer: accessToken)
        )
        guard let sub = response.sub else {
            throw SessionError.providerError("Missing subject claim in userinfo response")
        }
        let displayName = response.name
            ?? [response.given_name, response.family_name]
                .compactMap { $0 }
                .joined(separator: " ")
                .nonEmpty
            ?? response.preferred_username
            ?? sub
        return SessionUser(
            id:          sub,
            displayName: displayName,
            email:       response.email,
            avatarURL:   response.picture.flatMap { URL(string: $0) }
        )
    }

    // MARK: - Token Mapping

    private func mapToken(_ r: EnzonaTokenResponse) -> BearerToken {
        let scopes    = r.scope.map { $0.split(separator: " ").map(String.init) } ?? []
        let expiresAt = r.expires_in.map { Date().addingTimeInterval(TimeInterval($0)) }
        return BearerToken(
            accessToken:  r.access_token,
            refreshToken: r.refresh_token,
            expiresAt:    expiresAt,
            tokenType:    r.token_type ?? "Bearer",
            scopes:       scopes
        )
    }

    // MARK: - Cookie Helpers

    private func injectCookieIntoStorageIfNeeded(_ value: String) {
        // If the cookie already exists with the same value, leave it untouched
        // so its existing expiry is preserved.
        let existing = HTTPCookieStorage.shared.cookies?
            .first { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
        if existing?.value == value { return }

        // Use a 1-year expiry so the cookie is persisted across process restarts
        // (session-only cookies are lost on app exit).
        let expiry = Date().addingTimeInterval(365 * 24 * 3600)
        let properties: [HTTPCookiePropertyKey: Any] = [
            .name:    "deviceAuth",
            .value:   value,
            .domain:  "identity.enzona.net",
            .path:    "/",
            .secure:  "TRUE",
            .expires: expiry,
        ]
        if let cookie = HTTPCookie(properties: properties) {
            HTTPCookieStorage.shared.setCookie(cookie)
        }
    }

    private func removeFromCookieStorage() {
        HTTPCookieStorage.shared.cookies?
            .filter { $0.name == "deviceAuth" && $0.domain.contains("enzona.net") }
            .forEach { HTTPCookieStorage.shared.deleteCookie($0) }
    }

    // MARK: - PKCE Helpers

    private static func generateCodeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncoded()
    }

    private static func codeChallenge(for verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded()
    }

    // MARK: - Request Builders

    private func postRequest(_ url: URL, form params: [String: String]) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = formEncode(params)
        return request
    }

    private func getRequest(_ url: URL, bearer token: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return request
    }

    // MARK: - Network Helpers

    @discardableResult
    private func send(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await networkHandler(request)
        guard let http = response as? HTTPURLResponse else {
            throw SessionError.providerError("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 || http.statusCode == 403 {
                throw SessionError.invalidCredentials
            }
            if let errorBody = try? JSONDecoder().decode(EnzonaErrorResponse.self, from: data) {
                switch errorBody.error {
                case "invalid_grant", "invalid_client", "unauthorized_client":
                    throw SessionError.invalidCredentials
                default:
                    let description = errorBody.error_description ?? errorBody.error
                    throw SessionError.providerError("HTTP \(http.statusCode): \(description)")
                }
            }
            let body = String(data: data, encoding: .utf8) ?? "No body"
            throw SessionError.providerError("HTTP \(http.statusCode): \(body)")
        }
        return data
    }

    private func decode<T: Decodable>(_ type: T.Type, from request: URLRequest) async throws -> T {
        let data = try await send(request)
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw SessionError.providerError("Response decode failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Form Encoding

    private func formEncode(_ params: [String: String]) -> Data {
        params
            .sorted { $0.key < $1.key }
            .map { "\($0.key.formEncoded)=\($0.value.formEncoded)" }
            .joined(separator: "&")
            .data(using: .utf8) ?? Data()
    }
}

// MARK: - String helpers

private extension String {
    var formEncoded: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }

    /// `nil` when the string is empty after trimming whitespace.
    var nonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }
}

// MARK: - Data + base64url (RFC 4648 §5, no padding)

private extension Data {
    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
