// MARK: - OAuth2Provider.swift
//
// A standard OAuth2 Authorization Code + PKCE identity provider
// built on plain URLSession — no external dependencies.
//
// Works with any RFC 6749 / RFC 7636 compliant authorization server
// (Auth0, Okta, Keycloak, Azure AD, custom servers, etc.).
//
// Usage:
//
//   let provider = OAuth2Provider(
//       configuration: .init(
//           clientID:           "your-client-id",
//           tokenEndpoint:      URL(string: "https://auth.example.com/oauth/token")!,
//           revocationEndpoint: URL(string: "https://auth.example.com/oauth/revoke")!,
//           userInfoEndpoint:   URL(string: "https://auth.example.com/userinfo")!
//       )
//   )
//
//   let session = UserSessionManager(
//       provider: provider,
//       store:    KeychainCredentialStore<BearerToken>()
//   )
//
// Sign-in credential:
//   Use OAuthCredential with the authorization code from your UI flow
//   (ASWebAuthenticationSession, SFSafariViewController, etc.):
//
//   let credential = OAuthCredential(
//       provider:    "my-server",
//       idToken:     authorizationCode,   // the code, not a JWT
//       accessToken: nil,
//       nonce:       codeVerifier         // PKCE code_verifier
//   )
//   await session.signIn(with: credential)

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

    /// Token endpoint — POST here to exchange code for tokens.
    public let tokenEndpoint: URL

    /// Revocation endpoint (RFC 7009). Set nil to skip server-side revocation on sign-out.
    public let revocationEndpoint: URL?

    /// UserInfo endpoint (OpenID Connect). Used to fetch user profile after token exchange.
    /// Set nil to return a minimal user without fetching profile data.
    public let userInfoEndpoint: URL?

    /// Redirect URI registered with the authorization server.
    public let redirectURI: String

    /// Additional scopes to request.
    public let additionalScopes: [String]

    public init(
        clientID:           String,
        tokenEndpoint:      URL,
        revocationEndpoint: URL?    = nil,
        userInfoEndpoint:   URL?    = nil,
        redirectURI:        String  = "",
        additionalScopes:   [String] = []
    ) {
        self.clientID           = clientID
        self.tokenEndpoint      = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.userInfoEndpoint   = userInfoEndpoint
        self.redirectURI        = redirectURI
        self.additionalScopes   = additionalScopes
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
public final class OAuth2Provider: IdentityProvider, Sendable {

    public typealias Credential = OAuthCredential
    public typealias Token      = BearerToken

    public let providerID: String

    private let config:     OAuth2Configuration
    private let urlSession: URLSession

    public init(
        configuration: OAuth2Configuration,
        providerID:    String     = "oauth2",
        session:       URLSession = .shared
    ) {
        self.config     = configuration
        self.providerID = providerID
        self.urlSession = session
    }

    // MARK: - Sign In (Authorization Code → Token Exchange)

    public func signIn(with credential: OAuthCredential) async throws -> AuthResult<BearerToken> {
        guard let codeVerifier = credential.nonce else {
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

        let data:     Data                = try await post(config.tokenEndpoint, form: params)
        let response: OAuth2TokenResponse = try decode(data)
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

        let data:     Data                = try await post(config.tokenEndpoint, form: params)
        let response: OAuth2TokenResponse = try decode(data)
        let newToken = mapToken(response)
        // Skip the userinfo round-trip when the engine already has the user cached.
        // Only fetch when currentUser is nil (e.g. session restore with no stored user).
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
        _ = try await post(revocationURL, form: params)
    }

    // MARK: - UserInfo

    private func fetchUserInfo(accessToken: String) async throws -> SessionUser {
        guard let userInfoURL = config.userInfoEndpoint else {
            throw SessionError.providerError("Cannot resolve user: userInfoEndpoint is not configured")
        }

        let data:     Data                    = try await get(userInfoURL, bearer: accessToken)
        let response: OAuth2UserInfoResponse  = try decode(data)
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
        let scopes   = r.scope.map { $0.split(separator: " ").map(String.init) } ?? []
        let expiresAt = r.expires_in.map { Date().addingTimeInterval(TimeInterval($0)) }
        return BearerToken(
            accessToken:  r.access_token,
            refreshToken: r.refresh_token,
            expiresAt:    expiresAt,
            tokenType:    r.token_type ?? "Bearer",
            scopes:       scopes
        )
    }

    // MARK: - Network helpers

    private func post(_ url: URL, form params: [String: String]) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = formEncode(params)
        return try await send(request)
    }

    private func get(_ url: URL, bearer token: String) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return try await send(request)
    }

    private func send(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw SessionError.providerError("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 || http.statusCode == 403 {
                throw SessionError.invalidCredentials
            }
            let body = String(data: data, encoding: .utf8) ?? "No body"
            throw SessionError.providerError("HTTP \(http.statusCode): \(body)")
        }
        return data
    }

    private func decode<T: Decodable>(_ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw SessionError.providerError("Response decode failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Form encoding

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
    /// Percent-encodes the string per RFC 3986 for use in a form-encoded body.
    /// Only unreserved characters (ALPHA / DIGIT / "-" / "." / "_" / "~") are left as-is.
    var formEncoded: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }
}
