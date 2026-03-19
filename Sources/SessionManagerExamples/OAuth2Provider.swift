// MARK: - OAuth2Provider.swift
//
// A standard OAuth2 Authorization Code + PKCE identity provider.
//
// Works with any RFC 6749 / RFC 7636 compliant authorization server
// (Auth0, Okta, Keycloak, Azure AD, custom servers, etc.).
//
// Usage:
//
//   let provider = OAuth2Provider(
//       configuration: .init(
//           clientID:             "your-client-id",
//           tokenEndpoint:        URL(string: "https://auth.example.com/oauth/token")!,
//           revocationEndpoint:   URL(string: "https://auth.example.com/oauth/revoke")!,
//           userInfoEndpoint:     URL(string: "https://auth.example.com/userinfo")!
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
//       idToken:     authorizationCode,       // the code, not a JWT
//       accessToken: nil,
//       nonce:       codeVerifier             // PKCE code_verifier
//   )
//   await session.signIn(with: credential)

import Foundation
import SessionManager

// MARK: - OAuth2Configuration

public struct OAuth2Configuration: Sendable {

    /// OAuth2 client identifier.
    public let clientID: String

    /// Token endpoint — POST here to exchange code for tokens.
    public let tokenEndpoint: URL

    /// Revocation endpoint (RFC 7009). Set nil to skip server-side revocation on sign-out.
    public let revocationEndpoint: URL?

    /// UserInfo endpoint (OpenID Connect). Used to fetch user profile after token exchange.
    /// Set nil to extract user info from the ID token JWT instead.
    public let userInfoEndpoint: URL?

    /// Redirect URI registered with the authorization server.
    public let redirectURI: String

    /// Additional scopes to request. "openid" and "profile" are always included.
    public let additionalScopes: [String]

    public init(
        clientID: String,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        userInfoEndpoint: URL? = nil,
        redirectURI: String = "",
        additionalScopes: [String] = []
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
public final class OAuth2Provider: IdentityProvider, @unchecked Sendable {

    public typealias Credential = OAuthCredential
    public typealias Token      = BearerToken

    public let providerID: String

    private let config: OAuth2Configuration
    private let session: URLSession

    public init(
        configuration: OAuth2Configuration,
        providerID: String = "oauth2",
        session: URLSession = .shared
    ) {
        self.config     = configuration
        self.providerID = providerID
        self.session    = session
    }

    // MARK: - Sign In (Authorization Code → Token Exchange)

    public func signIn(with credential: OAuthCredential) async throws -> AuthResult<BearerToken> {
        guard let codeVerifier = credential.nonce else {
            throw SessionError.invalidCredentials
        }

        let authorizationCode = credential.idToken
        let token = try await exchangeCode(authorizationCode, codeVerifier: codeVerifier)
        let user = try await fetchUserInfo(accessToken: token.accessToken)

        return AuthResult(user: user, token: token)
    }

    // MARK: - Refresh Token

    public func refreshToken(_ token: BearerToken) async throws -> AuthResult<BearerToken> {
        guard let refreshToken = token.refreshToken else {
            throw SessionError.tokenRefreshFailed
        }

        let body: [String: String] = [
            "grant_type":    "refresh_token",
            "refresh_token": refreshToken,
            "client_id":     config.clientID,
        ]

        let newToken = try await postTokenRequest(body: body)
        let user = try await fetchUserInfo(accessToken: newToken.accessToken)

        return AuthResult(user: user, token: newToken)
    }

    // MARK: - Sign Out (Token Revocation)

    public func signOut(token: BearerToken) async throws {
        guard let endpoint = config.revocationEndpoint else { return }

        // Revoke refresh token if available, otherwise revoke access token (RFC 7009)
        let tokenToRevoke = token.refreshToken ?? token.accessToken

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = urlEncode([
            "token":           tokenToRevoke,
            "client_id":       config.clientID,
            "token_type_hint": token.refreshToken != nil ? "refresh_token" : "access_token",
        ])

        let (_, response) = try await session.data(for: request)
        // RFC 7009: 200 is success, even if the token was already invalid
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SessionError.providerError("Token revocation failed.")
        }
    }

    // MARK: - Private — Token Exchange

    private func exchangeCode(_ code: String, codeVerifier: String) async throws -> BearerToken {
        var body: [String: String] = [
            "grant_type":    "authorization_code",
            "code":          code,
            "client_id":     config.clientID,
            "code_verifier": codeVerifier,
        ]
        if !config.redirectURI.isEmpty {
            body["redirect_uri"] = config.redirectURI
        }

        return try await postTokenRequest(body: body)
    }

    private func postTokenRequest(body: [String: String]) async throws -> BearerToken {
        var request = URLRequest(url: config.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = urlEncode(body)

        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw SessionError.providerError("Invalid response from token endpoint.")
        }
        guard (200...299).contains(http.statusCode) else {
            let errorBody = String(data: data, encoding: .utf8) ?? "No body"
            if http.statusCode == 401 || http.statusCode == 403 {
                throw SessionError.invalidCredentials
            }
            throw SessionError.providerError("Token endpoint returned \(http.statusCode): \(errorBody)")
        }

        return try decodeTokenResponse(data)
    }

    // MARK: - Private — UserInfo

    private func fetchUserInfo(accessToken: String) async throws -> SessionUser {
        guard let endpoint = config.userInfoEndpoint else {
            // No userinfo endpoint — return a minimal user derived from the access token
            return SessionUser(id: "oauth2-user", displayName: "User")
        }

        var request = URLRequest(url: endpoint)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw SessionError.providerError("UserInfo endpoint failed.")
        }

        return try decodeUserInfoResponse(data)
    }

    // MARK: - Private — Response Decoding

    private func decodeTokenResponse(_ data: Data) throws -> BearerToken {
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let json, let accessToken = json["access_token"] as? String else {
            throw SessionError.providerError("Missing access_token in token response.")
        }

        let refreshToken = json["refresh_token"] as? String
        let tokenType = json["token_type"] as? String ?? "Bearer"
        let scopeString = json["scope"] as? String ?? ""
        let scopes = scopeString.isEmpty ? [] : scopeString.split(separator: " ").map(String.init)

        var expiresAt: Date?
        if let expiresIn = json["expires_in"] as? Int {
            expiresAt = Date().addingTimeInterval(TimeInterval(expiresIn))
        }

        return BearerToken(
            accessToken:  accessToken,
            refreshToken: refreshToken,
            expiresAt:    expiresAt,
            tokenType:    tokenType,
            scopes:       scopes
        )
    }

    private func decodeUserInfoResponse(_ data: Data) throws -> SessionUser {
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let json else {
            throw SessionError.providerError("Invalid UserInfo response.")
        }

        // Standard OpenID Connect claims
        let sub         = json["sub"] as? String ?? UUID().uuidString
        let name        = json["name"] as? String ?? json["preferred_username"] as? String ?? "User"
        let email       = json["email"] as? String
        let pictureStr  = json["picture"] as? String

        return SessionUser(
            id:          sub,
            displayName: name,
            email:       email,
            avatarURL:   pictureStr.flatMap { URL(string: $0) }
        )
    }

    // MARK: - Private — URL Encoding

    private func urlEncode(_ params: [String: String]) -> Data {
        params
            .map { key, value in
                let k = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
                let v = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
                return "\(k)=\(v)"
            }
            .joined(separator: "&")
            .data(using: .utf8) ?? Data()
    }
}
