// MARK: - Protocols/AuthCredential.swift
//
// AuthCredential is the *input* side of IdentityProvider.
// Each provider declares `associatedtype Credential: AuthCredential`,
// binding sign-in to exactly one credential shape at compile time.

import Foundation

// MARK: - AuthCredential Protocol

/// Marker protocol for all sign-in credential types.
///
/// Conform your own type to `AuthCredential` when none of the built-in
/// credential types fit your identity provider's requirements.
/// The conforming type becomes the `Credential` associated type of your
/// `IdentityProvider`, enforcing at compile time that callers pass the
/// correct credential to `signIn(with:)`.
public protocol AuthCredential: Sendable, Equatable {}

// MARK: - Concrete Credentials

/// Email and password pair for traditional username/password backends.
public struct EmailPasswordCredential: AuthCredential {
    /// The user's email address.
    public let email: String
    /// The user's password (plaintext; never persisted by the framework).
    public let password: String

    public init(email: String, password: String) {
        self.email    = email
        self.password = password
    }
}

/// Credential produced by a third-party OAuth2 / OpenID Connect flow.
///
/// Use this type with providers such as Google, GitHub, or any custom
/// OAuth2 server. For the built-in `OAuth2Provider` (Authorization Code +
/// PKCE), map the fields as follows:
/// - `idToken` → the authorization code returned by the auth server
/// - `nonce`   → the PKCE `code_verifier`
public struct OAuthCredential: AuthCredential {
    /// A label identifying the OAuth2 provider (e.g. `"google"`, `"github"`).
    public let provider: String
    /// The ID token or authorization code from the OAuth2 flow.
    public let idToken: String
    /// An OAuth2 access token, if already obtained outside the standard flow.
    public let accessToken: String?
    /// The PKCE `code_verifier`, or a nonce for implicit flows.
    public let nonce: String?

    public init(provider: String, idToken: String, accessToken: String? = nil, nonce: String? = nil) {
        self.provider    = provider
        self.idToken     = idToken
        self.accessToken = accessToken
        self.nonce       = nonce
    }
}

/// Credential produced by Sign in with Apple (`ASAuthorizationAppleIDCredential`).
public struct AppleCredential: AuthCredential {
    /// The stable user identifier issued by Apple.
    public let userIdentifier: String
    /// The JSON Web Token signed by Apple's private key.
    public let identityToken: Data
    /// Single-use code used to obtain refresh tokens from Apple's servers.
    public let authorizationCode: Data
    /// The user's full name, provided only on first sign-in.
    public let fullName: String?
    /// The user's email, provided only on first sign-in.
    public let email: String?

    public init(userIdentifier: String, identityToken: Data, authorizationCode: Data,
                fullName: String? = nil, email: String? = nil) {
        self.userIdentifier    = userIdentifier
        self.identityToken     = identityToken
        self.authorizationCode = authorizationCode
        self.fullName          = fullName
        self.email             = email
    }
}

/// Phone number and one-time password for SMS-based authentication.
public struct PhoneOTPCredential: AuthCredential {
    /// The E.164-formatted phone number (e.g. `"+14155552671"`).
    public let phoneNumber: String
    /// The one-time password entered by the user.
    public let otp: String
    /// An opaque token returned by the server when the OTP was sent,
    /// used to correlate the verification request.
    public let verificationID: String

    public init(phoneNumber: String, otp: String, verificationID: String) {
        self.phoneNumber    = phoneNumber
        self.otp            = otp
        self.verificationID = verificationID
    }
}

/// Credential backed by local biometric or device passcode authentication.
///
/// Use with providers that verify identity locally (Face ID, Touch ID,
/// or device passcode) before performing a sensitive operation.
public struct BiometricCredential: AuthCredential {
    /// The reason string displayed in the system biometric prompt.
    public let localizedReason: String

    public init(localizedReason: String = "Authenticate to continue") {
        self.localizedReason = localizedReason
    }
}

/// A raw token string used to bootstrap a session from an externally
/// obtained token (e.g. a token issued by a CI system or test harness).
public struct TokenCredential: AuthCredential {
    /// The raw token value.
    public let rawToken: String
    /// A label identifying the issuing provider.
    public let provider: String

    public init(rawToken: String, provider: String) {
        self.rawToken = rawToken
        self.provider = provider
    }
}

