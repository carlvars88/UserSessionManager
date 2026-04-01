// MARK: - FirebaseProvider.swift
//
// A SessionManager identity provider backed by the Firebase Auth SDK.
// Conditionally compiled — this file is a no-op when FirebaseAuth is not
// available, so the IdentityProviders target stays free of hard dependencies.
//
// To use, add FirebaseAuth to your app target (Swift Package or CocoaPods),
// then import IdentityProviders — this provider is available automatically.
//
// Usage:
//
//   typealias AppSession = UserSessionManager<FirebaseProvider, KeychainCredentialStore<BearerToken>>
//
//   let session = AppSession(
//       provider: FirebaseProvider(),
//       store:    KeychainCredentialStore()
//   )
//
//   // Email / password
//   await session.signIn(with: .emailPassword(EmailPasswordCredential(email: "a@b.com", password: "…")))
//
//   // Google
//   await session.signIn(with: .google(OAuthCredential(provider: "google", idToken: googleIDToken, accessToken: googleAccessToken)))
//
//   // Apple
//   await session.signIn(with: .apple(AppleCredential(userIdentifier: uid, identityToken: tokenData, authorizationCode: codeData)))
//
//   // Phone OTP
//   await session.signIn(with: .phoneOTP(PhoneOTPCredential(phoneNumber: "+1…", otp: "123456", verificationID: vid)))
//
//   // Anonymous
//   await session.signIn(with: .anonymous)

#if canImport(FirebaseAuth)
import FirebaseAuth
import Foundation
import SessionManager

// MARK: - FirebaseCredential

/// The set of sign-in methods supported by Firebase Authentication.
///
/// Pass one of these cases to `session.signIn(with:)`. Each case wraps the
/// library's matching primitive credential type so callers keep a single,
/// strongly-typed credential at the call site:
///
/// ```swift
/// await session.signIn(with: .google(OAuthCredential(provider: "google", idToken: idToken, accessToken: accessToken)))
/// await session.signIn(with: .emailPassword(EmailPasswordCredential(email: "a@b.com", password: "…")))
/// await session.signIn(with: .anonymous)
/// ```
public enum FirebaseCredential: AuthCredential {
    /// Traditional email address and password sign-in.
    case emailPassword(EmailPasswordCredential)
    /// Sign In with Apple using an ASAuthorizationAppleIDCredential.
    case apple(AppleCredential)
    /// Google Sign-In using a Google ID token and access token.
    case google(OAuthCredential)
    /// Any other OAuth2 provider registered in the Firebase console (GitHub, Twitter, etc.).
    case oauth(OAuthCredential)
    /// Phone number verification using an SMS one-time password.
    case phoneOTP(PhoneOTPCredential)
    /// Anonymous guest session — Firebase creates a temporary account.
    case anonymous
}

// MARK: - FirebaseProvider

/// An `IdentityProvider` that delegates all authentication to the Firebase Auth SDK.
///
/// Credential: `FirebaseCredential` — choose `.emailPassword`, `.apple`,
/// `.google`, `.oauth`, `.phoneOTP`, or `.anonymous`.
///
/// Token: `BearerToken`
///   - `accessToken`  → Firebase ID token (JWT)
///   - `refreshToken` → Firebase refresh token (opaque)
///   - `expiresAt`    → expiry from `IDTokenResult.expirationDate`
///
/// `currentToken()` is overridden to query the Firebase SDK's in-process
/// cache, enabling the session manager to restore a session on app launch
/// without a network call when Firebase already holds a valid token.
public final class FirebaseProvider: IdentityProvider, Sendable {

    public typealias Credential = FirebaseCredential
    public typealias Token      = BearerToken

    public let providerID = "firebase"

    public init() {}

    // MARK: - currentToken (Firebase in-process cache)

    /// Returns the Firebase SDK's cached token without forcing a network refresh.
    ///
    /// The session manager calls this first during session restore. If Firebase
    /// already has a valid, non-expired token the session is restored immediately
    /// without hitting the network. A forced refresh is only triggered later if
    /// `SessionManagerEngine` determines the token is expired or near expiry.
    public func currentToken() async -> BearerToken? {
        guard let user = Auth.auth().currentUser,
              let result = try? await user.getIDTokenResult(forcingRefresh: false)
        else { return nil }

        return BearerToken(
            accessToken:  result.token,
            refreshToken: user.refreshToken,
            expiresAt:    result.expirationDate,
            tokenType:    "Bearer",
            scopes:       []
        )
    }

    // MARK: - Sign In

    public func signIn(with credential: FirebaseCredential) async throws -> AuthResult<BearerToken> {
        do {
            let result: AuthDataResult
            if case .anonymous = credential {
                result = try await Auth.auth().signInAnonymously()
            } else {
                result = try await Auth.auth().signIn(with: try firebaseAuthCredential(from: credential))
            }
            return try await makeAuthResult(from: result)
        } catch let error as SessionError {
            throw error
        } catch let error as NSError {
            throw mapFirebaseError(error)
        }
    }

    // MARK: - Refresh Token

    /// Forces a Firebase ID token refresh.
    ///
    /// Firebase manages its own refresh token internally — this method simply
    /// asks the SDK for a fresh ID token. When `currentUser` is already cached
    /// by the engine it is returned unchanged; a Firebase `currentUser` lookup
    /// is only performed when `currentUser` is `nil` (e.g. session restore with
    /// no persisted `SessionUser`).
    public func refreshToken(_ token: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> {
        guard let user = Auth.auth().currentUser else {
            throw SessionError.sessionNotFound
        }

        do {
            let result = try await user.getIDTokenResult(forcingRefresh: true)
            let newToken = BearerToken(
                accessToken:  result.token,
                refreshToken: user.refreshToken,
                expiresAt:    result.expirationDate,
                tokenType:    "Bearer",
                scopes:       []
            )
            return AuthResult(user: currentUser ?? mapUser(user), token: newToken)
        } catch let error as NSError {
            throw mapFirebaseError(error)
        }
    }

    // MARK: - Reauthenticate

    /// Re-authenticates the current Firebase user before a sensitive operation.
    ///
    /// Uses `User.reauthenticate(with:)` rather than a full sign-in, so the
    /// UID is preserved and the server-side session is not replaced.
    /// Anonymous sessions cannot reauthenticate — link a credential first.
    public func reauthenticate(user: SessionUser, with credential: FirebaseCredential) async throws -> AuthResult<BearerToken> {
        guard let firebaseUser = Auth.auth().currentUser else {
            throw SessionError.sessionNotFound
        }
        guard case .anonymous = credential else {
            do {
                let result = try await firebaseUser.reauthenticate(with: try firebaseAuthCredential(from: credential))
                return try await makeAuthResult(from: result)
            } catch let error as SessionError {
                throw error
            } catch let error as NSError {
                throw mapFirebaseError(error)
            }
        }
        throw SessionError.providerError("Anonymous sessions cannot reauthenticate — link a credential first.")
    }

    // MARK: - Sign Out

    public func signOut(token: BearerToken) async throws {
        do {
            try Auth.auth().signOut()
        } catch let error as NSError {
            throw SessionError.providerError("Firebase sign-out failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Private helpers

    /// Maps a `FirebaseCredential` case to the matching `FirebaseAuth.AuthCredential`.
    private func firebaseAuthCredential(from credential: FirebaseCredential) throws -> FirebaseAuth.AuthCredential {
        switch credential {

        case .emailPassword(let c):
            return EmailAuthProvider.credential(withEmail: c.email, password: c.password)

        case .apple(let c):
            guard let idToken = String(data: c.identityToken, encoding: .utf8) else {
                throw SessionError.invalidCredentials
            }
            // fullName is a String? in AppleCredential; OAuthProvider expects PersonNameComponents?.
            // Pass nil — the name is only needed on first sign-in and is already captured
            // in the SessionUser returned by makeAuthResult.
            return OAuthProvider.appleCredential(withIDToken: idToken, rawNonce: nil, fullName: nil)

        case .google(let c):
            return GoogleAuthProvider.credential(
                withIDToken:   c.idToken,
                accessToken:   c.accessToken ?? ""
            )

        case .oauth(let c):
            return OAuthProvider.credential(
                withProviderID: c.provider,
                idToken:        c.idToken,
                accessToken:    c.accessToken
            )

        case .phoneOTP(let c):
            return PhoneAuthProvider.provider().credential(
                withVerificationID:   c.verificationID,
                verificationCode:     c.otp
            )

        case .anonymous:
            // Anonymous sign-in bypasses this path — handled directly in signIn(_:).
            throw SessionError.providerError("Anonymous sign-in does not use a credential.")
        }
    }

    /// Extracts a fresh ID token from an `AuthDataResult` and packages it as an `AuthResult`.
    private func makeAuthResult(from result: AuthDataResult) async throws -> AuthResult<BearerToken> {
        let tokenResult = try await result.user.getIDTokenResult(forcingRefresh: false)
        let token = BearerToken(
            accessToken:  tokenResult.token,
            refreshToken: result.user.refreshToken,
            expiresAt:    tokenResult.expirationDate,
            tokenType:    "Bearer",
            scopes:       []
        )
        return AuthResult(user: mapUser(result.user), token: token)
    }

    /// Maps a Firebase `User` to the library's `SessionUser`.
    private func mapUser(_ user: FirebaseAuth.User) -> SessionUser {
        SessionUser(
            id:          user.uid,
            displayName: user.displayName ?? user.email ?? user.phoneNumber ?? "User",
            email:       user.email,
            avatarURL:   user.photoURL
        )
    }

    /// Translates Firebase `NSError` values into `SessionError`.
    private func mapFirebaseError(_ error: NSError) -> SessionError {
        guard error.domain == AuthErrorDomain else {
            return .providerError(error.localizedDescription)
        }
        switch AuthErrorCode(rawValue: error.code) {
        case .wrongPassword,
             .invalidCredential,
             .userNotFound,
             .invalidEmail,
             .accountExistsWithDifferentCredential,
             .credentialAlreadyInUse:
            return .invalidCredentials
        case .networkError:
            return .providerError("Network error — check your connection.")
        case .tooManyRequests:
            return .providerError("Too many attempts — try again later.")
        case .userDisabled:
            return .providerError("This account has been disabled.")
        default:
            return .providerError(error.localizedDescription)
        }
    }
}
#endif
