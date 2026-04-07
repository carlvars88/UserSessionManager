// MARK: - OAuth2Provider.swift
//
// A standard OAuth2 Authorization Code + PKCE identity provider.
// Works with any RFC 6749 / RFC 7636 compliant authorization server
// (Auth0, Okta, Keycloak, Azure AD, custom servers, etc.).
//
// Usage:
//
//   let provider = OAuth2Provider(
//       configuration: .init(
//           clientID:              "your-client-id",
//           authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
//           tokenEndpoint:         URL(string: "https://auth.example.com/oauth/token")!,
//           revocationEndpoint:    URL(string: "https://auth.example.com/oauth/revoke")!,
//           userInfoEndpoint:      URL(string: "https://auth.example.com/userinfo")!,
//           redirectURI:           "myapp://callback",
//           additionalScopes:      ["openid", "profile"]
//       ),
//       networkHandler: URLSession.shared.data(for:)
//   )
//
//   let session = UserSessionManager(provider: provider, store: KeychainCredentialStore<BearerToken>())
//
//   // 1. Build the authorization URL (generates PKCE + state internally)
//   let authURL = try await provider.authorizationRequest()
//
//   // 2. Open authURL in ASWebAuthenticationSession / SFSafariViewController
//   //    On callback, extract `code` and `state` from the redirect URL:
//   //
//   //      let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)
//   //      let code          = components?.queryItems?.first(where: { $0.name == "code" })?.value ?? ""
//   //      let returnedState = components?.queryItems?.first(where: { $0.name == "state" })?.value
//
//   // 3. Sign in — state is validated inside signIn before any network call
//   let credential = OAuthCredential(provider: "my-server", idToken: code, state: returnedState)
//   await session.signIn(with: credential)

import CryptoKit
import Foundation
import SessionManager

// MARK: - Private response shapes

private struct OAuth2TokenResponse: Decodable {
    let access_token:  String
    let refresh_token: String?
    let token_type:    String?
    let expires_in:    Int?
    let scope:         String?
}

private struct OAuth2ErrorResponse: Decodable {
    let error:             String
    let error_description: String?
}

private struct OAuth2UserInfoResponse: Decodable {
    let sub:                String?
    let name:               String?
    let preferred_username: String?
    let email:              String?
    let picture:            String?
}

// MARK: - OAuth2Configuration

public struct OAuth2Configuration: Sendable {

    /// OAuth2 client identifier.
    public let clientID: String

    /// Authorization endpoint — the browser URL that starts the OAuth2 flow.
    /// Required to use `OAuth2Provider.authorizationRequest(state:)`.
    public let authorizationEndpoint: URL?

    /// Token endpoint — POST here to exchange code for tokens.
    public let tokenEndpoint: URL

    /// Revocation endpoint (RFC 7009). Set nil to skip server-side revocation on sign-out.
    public let revocationEndpoint: URL?

    /// UserInfo endpoint (OpenID Connect). Used to fetch user profile after token exchange.
    /// Set nil to return a minimal user without fetching profile data.
    public let userInfoEndpoint: URL?

    /// Redirect URI registered with the authorization server.
    public let redirectURI: String

    /// Additional scopes to request (e.g. `["openid", "profile", "email"]`).
    public let additionalScopes: [String]

    /// Query parameter name for the PKCE challenge sent in the authorization URL.
    /// RFC 7636 specifies `"code_challenge"`. Set to `"code_challange"` for servers
    /// with the common typo (e.g. enzona.net).
    public let codeChallengeParameterName: String

    /// Query parameter name for the PKCE challenge method sent in the authorization URL.
    /// RFC 7636 specifies `"code_challenge_method"`. Set to `"code_challange_method"`
    /// for servers with the common typo (e.g. enzona.net).
    public let codeChallengeMethodParameterName: String

    public init(
        clientID:                       String,
        authorizationEndpoint:          URL?     = nil,
        tokenEndpoint:                  URL,
        revocationEndpoint:             URL?     = nil,
        userInfoEndpoint:               URL?     = nil,
        redirectURI:                    String   = "",
        additionalScopes:               [String] = [],
        codeChallengeParameterName:     String   = "code_challenge",
        codeChallengeMethodParameterName: String = "code_challenge_method"
    ) {
        self.clientID                        = clientID
        self.authorizationEndpoint           = authorizationEndpoint
        self.tokenEndpoint                   = tokenEndpoint
        self.revocationEndpoint              = revocationEndpoint
        self.userInfoEndpoint                = userInfoEndpoint
        self.redirectURI                     = redirectURI
        self.additionalScopes                = additionalScopes
        self.codeChallengeParameterName      = codeChallengeParameterName
        self.codeChallengeMethodParameterName = codeChallengeMethodParameterName
    }
}

// MARK: - OAuth2Provider

/// Standard OAuth2 Authorization Code + PKCE provider.
///
/// Credential: `OAuthCredential`
///   - `idToken`     → the authorization code from your auth UI flow
///   - `nonce`       → the PKCE code_verifier (required)
///   - `provider`    → descriptive label (e.g. "my-server")
///   - `accessToken` → unused for sign-in; leave nil
///
/// Token: `BearerToken`
///   - `accessToken`  → the OAuth2 access token
///   - `refreshToken` → the OAuth2 refresh token (if granted)
///   - `expiresAt`    → computed from `expires_in`
///   - `scopes`       → granted scopes
///
/// Pass any `SMNetworkHandler` — `URLSession`, Alamofire, or a test stub:
///
/// ```swift
/// // URLSession (default)
/// OAuth2Provider(configuration: config, networkHandler: URLSession.shared.data(for:))
///
/// // SSL pinning
/// let pinned = URLSession(configuration: .default, delegate: PinningDelegate(), delegateQueue: nil)
/// OAuth2Provider(configuration: config, networkHandler: pinned.data(for:))
///
/// // Alamofire
/// OAuth2Provider(configuration: config) { request in
///     let data = try await AF.request(request).serializingData().value
///     return (data, AF.request(request).response!)
/// }
///
/// // Test stub
/// OAuth2Provider(configuration: config) { _ in (tokenJSON, HTTPURLResponse(...)) }
/// ```
public actor OAuth2Provider: IdentityProvider {

    public typealias Credential = OAuthCredential
    public typealias Token      = BearerToken

    // nonisolated let satisfies the non-async protocol requirement from outside the actor.
    public nonisolated let providerID: String

    private let config:         OAuth2Configuration
    private let networkHandler: SMNetworkHandler

    // Pending PKCE state set by authorizationRequest, consumed by signIn.
    // Actor isolation replaces the previous nonisolated(unsafe) + @unchecked Sendable.
    private var pendingCodeVerifier:  String?
    private var pendingExpectedState: String?

    /// Creates an `OAuth2Provider`.
    ///
    /// - Parameters:
    ///   - configuration: OAuth2 server endpoints and client settings.
    ///   - providerID: Label used in log messages. Defaults to `"oauth2"`.
    ///   - networkHandler: The closure used for all network calls. Pass
    ///     `URLSession.shared.data(for:)`, a pinned session's `data(for:)`,
    ///     an Alamofire wrapper, or a stub for tests.
    public init(
        configuration:  OAuth2Configuration,
        providerID:     String           = "oauth2",
        networkHandler: @escaping SMNetworkHandler
    ) {
        self.config         = configuration
        self.providerID     = providerID
        self.networkHandler = networkHandler
    }

    // MARK: - Authorization Request (PKCE)

    /// Builds a PKCE authorization URL to open in a browser or `ASWebAuthenticationSession`.
    ///
    /// Generates a cryptographically random `code_verifier` and derives the
    /// `code_challenge` via SHA-256 (S256). Both the verifier and `state` are
    /// stored internally and consumed by the next `signIn(with:)` call — the
    /// caller does not need to handle them directly.
    ///
    /// After the server redirects back, extract `code` and `state` from the
    /// callback URL and pass them to `signIn(with:)` via `OAuthCredential`:
    ///
    /// ```swift
    /// let authURL = try await provider.authorizationRequest()
    /// // present authURL, receive callbackURL
    /// let items         = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems
    /// let code          = items?.first(where: { $0.name == "code" })?.value ?? ""
    /// let returnedState = items?.first(where: { $0.name == "state" })?.value
    /// await session.signIn(with: OAuthCredential(provider: "my-server", idToken: code, state: returnedState))
    /// ```
    ///
    /// - Parameter state: Anti-CSRF token embedded in the URL. Defaults to a random UUID.
    /// - Throws: `SessionError.providerError` if `authorizationEndpoint` is not configured.
    public func authorizationRequest(state: String = UUID().uuidString) throws -> URL {
        guard let authorizationEndpoint = config.authorizationEndpoint else {
            throw SessionError.providerError("authorizationEndpoint is not configured")
        }

        let codeVerifier  = Self.generateCodeVerifier()
        let codeChallenge = Self.codeChallenge(for: codeVerifier)

        pendingCodeVerifier  = codeVerifier
        pendingExpectedState = state

        guard var components = URLComponents(url: authorizationEndpoint, resolvingAgainstBaseURL: false) else {
            throw SessionError.providerError("Invalid authorizationEndpoint URL")
        }

        var items: [URLQueryItem] = [
            URLQueryItem(name: "response_type",                         value: "code"),
            URLQueryItem(name: "client_id",                             value: config.clientID),
            URLQueryItem(name: config.codeChallengeParameterName,       value: codeChallenge),
            URLQueryItem(name: config.codeChallengeMethodParameterName, value: "S256"),
            URLQueryItem(name: "state",                                 value: state),
        ]
        if !config.redirectURI.isEmpty {
            items.append(URLQueryItem(name: "redirect_uri", value: config.redirectURI))
        }
        if !config.additionalScopes.isEmpty {
            items.append(URLQueryItem(name: "scope", value: config.additionalScopes.joined(separator: " ")))
        }
        components.queryItems = items

        guard let url = components.url else {
            throw SessionError.providerError("Failed to build authorization URL")
        }

        return url
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

    // MARK: - Sign In (Authorization Code → Token Exchange)

    public func signIn(with credential: OAuthCredential) async throws -> AuthResult<BearerToken> {
        // Consume the pending PKCE state stored by authorizationRequest.
        let storedVerifier      = pendingCodeVerifier
        let storedExpectedState = pendingExpectedState
        pendingCodeVerifier     = nil
        pendingExpectedState    = nil

        // State validation: if the server echoed state back it must match.
        // Skipped when credential.state is nil (server doesn't support state).
        if let returnedState = credential.state, returnedState != storedExpectedState {
            throw SessionError.providerError("State mismatch — possible CSRF attack")
        }

        // Use the verifier stored by authorizationRequest, or fall back to
        // credential.nonce for callers that manage PKCE manually.
        guard let codeVerifier = storedVerifier ?? credential.nonce else {
            throw SessionError.invalidCredentials
        }

        var params: [String: String] = [
            "grant_type":    "authorization_code",
            "code":          credential.idToken,
            "client_id":     config.clientID,
            "code_verifier": codeVerifier,
        ]
        if !config.redirectURI.isEmpty {
            params["redirect_uri"] = config.redirectURI
        }

        let response: OAuth2TokenResponse = try await decode(
            OAuth2TokenResponse.self,
            from: postRequest(config.tokenEndpoint, form: params)
        )
        let token = mapToken(response)
        let user  = try await fetchUserInfo(accessToken: token.accessToken)
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
            "client_id":     config.clientID,
        ]

        let response: OAuth2TokenResponse = try await decode(
            OAuth2TokenResponse.self,
            from: postRequest(config.tokenEndpoint, form: params)
        )
        let newToken = mapToken(response)
        let user = if let currentUser {
            currentUser
        } else {
            try await fetchUserInfo(accessToken: newToken.accessToken)
        }
        return AuthResult(user: user, token: newToken)
    }

    // MARK: - Sign Out (Token Revocation)

    public func signOut(token: BearerToken) async throws {
        guard let revocationURL = config.revocationEndpoint else { return }

        let params: [String: String] = [
            "token":           token.refreshToken ?? token.accessToken,
            "client_id":       config.clientID,
            "token_type_hint": token.refreshToken != nil ? "refresh_token" : "access_token",
        ]
        try await send(postRequest(revocationURL, form: params))
    }

    // MARK: - UserInfo

    private func fetchUserInfo(accessToken: String) async throws -> SessionUser {
        guard let userInfoURL = config.userInfoEndpoint else {
            throw SessionError.providerError("Cannot resolve user: userInfoEndpoint is not configured")
        }

        let response: OAuth2UserInfoResponse = try await decode(
            OAuth2UserInfoResponse.self,
            from: getRequest(userInfoURL, bearer: accessToken)
        )
        guard let sub = response.sub else {
            throw SessionError.providerError("Missing subject claim")
        }
        return SessionUser(
            id:          sub,
            displayName: response.name ?? response.preferred_username ?? "User",
            email:       response.email,
            avatarURL:   response.picture.flatMap { URL(string: $0) }
        )
    }

    // MARK: - Token Mapping

    private func mapToken(_ r: OAuth2TokenResponse) -> BearerToken {
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
            // Try to parse an OAuth2 error body (RFC 6749 §5.2).
            // Permanent errors map to .invalidCredentials so the engine
            // clears the store and transitions to .expired instead of
            // retrying indefinitely as if the failure were transient.
            if let errorBody = try? JSONDecoder().decode(OAuth2ErrorResponse.self, from: data) {
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

// MARK: - String + application/x-www-form-urlencoded

private extension String {
    var formEncoded: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return addingPercentEncoding(withAllowedCharacters: allowed) ?? self
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
