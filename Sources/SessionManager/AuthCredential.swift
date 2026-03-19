// MARK: - Protocols/AuthCredential.swift
//
// AuthCredential is the *input* side of IdentityProvider.
// Each provider declares `associatedtype Credential: AuthCredential`,
// binding sign-in to exactly one credential shape at compile time.

import Foundation

// MARK: - AuthCredential Protocol

public protocol AuthCredential: Sendable, Equatable {}

// MARK: - Concrete Credentials

public struct EmailPasswordCredential: AuthCredential {
    public let email: String
    public let password: String
    public init(email: String, password: String) {
        self.email    = email
        self.password = password
    }
}

public struct OAuthCredential: AuthCredential {
    public let provider: String
    public let idToken: String
    public let accessToken: String?
    public let nonce: String?
    public init(provider: String, idToken: String, accessToken: String? = nil, nonce: String? = nil) {
        self.provider    = provider
        self.idToken     = idToken
        self.accessToken = accessToken
        self.nonce       = nonce
    }
}

public struct AppleCredential: AuthCredential {
    public let userIdentifier: String
    public let identityToken: Data
    public let authorizationCode: Data
    public let fullName: String?
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

public struct PhoneOTPCredential: AuthCredential {
    public let phoneNumber: String
    public let otp: String
    public let verificationID: String
    public init(phoneNumber: String, otp: String, verificationID: String) {
        self.phoneNumber    = phoneNumber
        self.otp            = otp
        self.verificationID = verificationID
    }
}

public struct BiometricCredential: AuthCredential {
    public let localizedReason: String
    public init(localizedReason: String = "Authenticate to continue") {
        self.localizedReason = localizedReason
    }
}

public struct TokenCredential: AuthCredential {
    public let rawToken: String
    public let provider: String
    public init(rawToken: String, provider: String) {
        self.rawToken = rawToken
        self.provider = provider
    }
}

// MARK: - MultiCredential
//
// For providers that accept more than one credential type:
//   typealias Credential = MultiCredential<EmailPasswordCredential, OAuthCredential>

public enum MultiCredential<First: AuthCredential, Second: AuthCredential>: AuthCredential {
    case first(First)
    case second(Second)
}
