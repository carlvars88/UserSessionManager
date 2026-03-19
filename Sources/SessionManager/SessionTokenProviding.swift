// MARK: - Protocols/SessionTokenProviding.swift
//
// The networking layer's only dependency on the session system.
//
// Now generic over Token so APIClient can be typed to the token shape it actually
// uses (e.g. BearerToken for Authorization header injection, CookieToken as a
// signal-only type, OpaqueSessionToken for custom header injection).
//
// Because Token: AuthSessionToken has no PAP-causing requirements beyond what
// the concrete APIClient already knows, existential `any SessionTokenProviding`
// works fine for simple cases. For full type erasure use AnyTokenProvider below.
//
// Injection examples:
//
//   // Concrete — APIClient knows it works with BearerToken
//   struct APIClient {
//       let tokens: any SessionTokenProviding<BearerToken>
//   }
//
//   // Erased — APIClient needs no knowledge of the token shape
//   struct APIClient {
//       let tokens: AnyTokenProvider
//       // uses tokens.currentRawToken() → String for header injection
//   }

import Foundation

// MARK: - SessionTokenProviding

public protocol SessionTokenProviding<Token>: AnyObject, Sendable {
    associatedtype Token: AuthSessionToken
    func currentValidToken() async throws -> Token
}

// MARK: - AnyTokenProvider
//
// Type-erases SessionTokenProviding<Token> down to a single string accessor.
// Use when the networking layer only needs to inject a header value and has
// no interest in the token's shape or lifecycle.
//
// Supports BearerToken (Authorization: Bearer <accessToken>),
//          OpaqueSessionToken (X-Session-Token: <value>),
//          CookieToken (no header — cookies handled by URLSession automatically).

public final class AnyTokenProvider: Sendable {

    private let _rawValue: @Sendable () async throws -> String?

    /// - Parameter rawValue: closure that returns the header-injectable string,
    ///   or nil if the token needs no header (e.g. CookieToken).
    public init<P: SessionTokenProviding>(
        _ provider: P,
        rawValue: @escaping @Sendable (P.Token) -> String?
    ) {
        _rawValue = { [weak provider] in
            guard let provider else { throw SessionError.unknown("Provider deallocated") }
            let token = try await provider.currentValidToken()
            return rawValue(token)
        }
    }

    /// Returns the injectable header value, or nil for cookie-based sessions.
    public func currentRawToken() async throws -> String? {
        try await _rawValue()
    }
}

// MARK: - Convenience AnyTokenProvider initialisers

public extension AnyTokenProvider {

    /// For BearerToken providers — returns the accessToken string.
    convenience init<P: SessionTokenProviding>(_ provider: P) where P.Token == BearerToken {
        self.init(provider, rawValue: { $0.accessToken })
    }

    /// For OpaqueSessionToken providers — returns the value string.
    convenience init<P: SessionTokenProviding>(_ provider: P) where P.Token == OpaqueSessionToken {
        self.init(provider, rawValue: { $0.value })
    }

    /// For CookieToken providers — no header needed, returns nil.
    convenience init<P: SessionTokenProviding>(_ provider: P) where P.Token == CookieToken {
        self.init(provider, rawValue: { _ in nil })
    }
}

// MARK: - MockTokenProvider  (networking unit tests)
//
// Generic over Token so networking tests can use any token shape without
// any dependency on IdentityProvider, CredentialStore, or UserSessionManager.

public final class MockTokenProvider<Token: AuthSessionToken>:
    SessionTokenProviding, @unchecked Sendable
{
    public enum Behaviour {
        case success(Token)
        case failure(SessionError)
        case expiresThenSucceeds(Token)
    }

    private let behaviour: Behaviour
    private var callCount = 0

    public init(_ behaviour: Behaviour) {
        self.behaviour = behaviour
    }

    public func currentValidToken() async throws -> Token {
        callCount += 1
        switch behaviour {
        case .success(let token):
            return token
        case .failure(let error):
            throw error
        case .expiresThenSucceeds(let token):
            if callCount == 1 { throw SessionError.tokenRefreshFailed }
            return token
        }
    }
}
