// MARK: - Providers/FirebaseIdentityProvider.swift
//
// Three Firebase adapters demonstrating all three token shapes.
// Only this file imports FirebaseAuth — the rest of the app never does.

import Foundation
@testable import SessionManager
// import FirebaseAuth

// MARK: - FirebaseEmailProvider  (BearerToken — Firebase ID token is a JWT)

public final class FirebaseEmailProvider: IdentityProvider, @unchecked Sendable {

    public typealias Credential = EmailPasswordCredential
    public typealias Token      = BearerToken              // Firebase ID token is a JWT Bearer

    public let providerID = "firebase-email"

    public init() {}

    public func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
        // let result = try await Auth.auth().signIn(withEmail: credential.email,
        //                                           password: credential.password)
        // return AuthResult(user: map(result.user), token: try await bearerToken(result.user))
        throw SessionError.providerError("FirebaseAuth not linked.")
    }

    public func refreshToken(_ token: BearerToken) async throws -> AuthResult<BearerToken> {
        // guard let user = Auth.auth().currentUser else { throw SessionError.sessionNotFound }
        // let idToken = try await user.getIDTokenForcingRefresh(true)
        // return AuthResult(user: map(user), token: BearerToken(accessToken: idToken,
        //                                                        expiresAt: Date.now.addingTimeInterval(3600)))
        throw SessionError.providerError("FirebaseAuth not linked.")
    }

    public func signOut(token: BearerToken) async throws {
        // try Auth.auth().signOut()
    }

    public func currentToken() async -> BearerToken? {
        // guard let user = Auth.auth().currentUser,
        //       let raw  = try? await user.getIDToken()
        // else { return nil }
        // return BearerToken(accessToken: raw, expiresAt: Date.now.addingTimeInterval(3600))
        return nil
    }
}

// MARK: - CustomBackendProvider  (OpaqueSessionToken — username/password, no OAuth)
//
// A plain username+password backend that returns a single opaque session token.
// No refresh token. Expiry causes re-login.

public final class CustomBackendProvider: IdentityProvider, @unchecked Sendable {

    public typealias Credential = EmailPasswordCredential
    public typealias Token      = OpaqueSessionToken       // ← not Bearer, not cookie

    public let providerID = "custom-backend"
    private let baseURL: URL

    public init(baseURL: URL) { self.baseURL = baseURL }

    public func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<OpaqueSessionToken> {
        // var req = URLRequest(url: baseURL.appending(path: "/auth/login"))
        // req.httpMethod = "POST"
        // req.httpBody   = try JSONEncoder().encode(["email": credential.email,
        //                                            "password": credential.password])
        // let (data, _)  = try await URLSession.shared.data(for: req)
        // let response   = try JSONDecoder().decode(LoginResponse.self, from: data)
        // let token      = OpaqueSessionToken(value: response.sessionToken,
        //                                    expiresAt: response.expiresAt)
        // let user       = SessionUser(id: response.userID, displayName: response.name,
        //                              email: credential.email)
        // return AuthResult(user: user, token: token)
        throw SessionError.providerError("CustomBackend not configured.")
    }

    // No refresh — opaque tokens are single-use until expiry
    public func refreshToken(_ token: OpaqueSessionToken) async throws -> AuthResult<OpaqueSessionToken> {
        throw SessionError.tokenRefreshFailed
    }

    public func signOut(token: OpaqueSessionToken) async throws {
        // POST /auth/logout with token in header
    }
}

// MARK: - CookieSessionProvider  (CookieToken — server manages everything via Set-Cookie)
//
// The server sets an HttpOnly cookie on login. The app carries no token data.
// URLSession sends the cookie automatically on every request.

public final class CookieSessionProvider: IdentityProvider, @unchecked Sendable {

    public typealias Credential = EmailPasswordCredential
    public typealias Token      = CookieToken              // ← presence signal only

    public let providerID = "cookie-session"
    private let baseURL: URL

    public init(baseURL: URL) { self.baseURL = baseURL }

    public func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<CookieToken> {
        // POST /auth/login — server responds with Set-Cookie: session_id=...
        // URLSession stores the cookie automatically in HTTPCookieStorage.shared
        // We just need to record that a session exists.
        //
        // let (_, response) = try await URLSession.shared.data(for: loginRequest(credential))
        // guard (response as? HTTPURLResponse)?.statusCode == 200 else {
        //     throw SessionError.invalidCredentials
        // }
        // // Read expiry from the cookie if available
        // let expiry = HTTPCookieStorage.shared.cookies?.first(where: { $0.name == "session_id" })?.expiresDate
        // let token  = CookieToken(cookieName: "session_id", expiresAt: expiry)
        // let user   = try await fetchCurrentUser()   // GET /me
        // return AuthResult(user: user, token: token)
        throw SessionError.providerError("CookieSessionProvider not configured.")
    }

    // Re-validate with the server — if cookie is still valid, return a fresh signal
    public func refreshToken(_ token: CookieToken) async throws -> AuthResult<CookieToken> {
        // GET /auth/refresh — server validates the cookie and returns updated user info
        // let (data, response) = try await URLSession.shared.data(for: refreshRequest())
        // guard (response as? HTTPURLResponse)?.statusCode == 200 else {
        //     throw SessionError.tokenRefreshFailed
        // }
        // let user = try JSONDecoder().decode(SessionUser.self, from: data)
        // return AuthResult(user: user, token: token)   // cookie unchanged
        throw SessionError.providerError("CookieSessionProvider not configured.")
    }

    public func signOut(token: CookieToken) async throws {
        // POST /auth/logout — server clears the cookie server-side
        // HTTPCookieStorage.shared.removeCookies(since: .distantPast)
    }
}
