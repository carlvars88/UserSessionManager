// MARK: - Protocols/CredentialStore.swift
//
// CredentialStore is now generic over Token.
//
// The constraint `Store.Token == Provider.Token` on UserSessionManager guarantees
// at compile time that a store built for BearerToken cannot be paired with a
// provider that produces OpaqueSessionToken. No runtime cast, no force-unwrap.
//
// Concrete stores are generic structs — one implementation covers all token shapes:
//
//   InMemoryCredentialStore<BearerToken>
//   InMemoryCredentialStore<OpaqueSessionToken>
//   KeychainCredentialStore<BearerToken>
//   KeychainCredentialStore<CookieToken>

import Foundation
import Security

// MARK: - CredentialStore Protocol

public protocol CredentialStore: Sendable {

    /// The token shape this store persists. Must match IdentityProvider.Token.
    associatedtype Token: AuthSessionToken

    func save(token: Token, user: SessionUser) async throws
    func load() async throws -> (token: Token, user: SessionUser)?
    func clear() async throws
}

// MARK: - InMemoryCredentialStore<Token>

public final class InMemoryCredentialStore<Token: AuthSessionToken>:
    CredentialStore, @unchecked Sendable
{
    private var stored: (token: Token, user: SessionUser)?

    public init() {}

    public func save(token: Token, user: SessionUser) async throws {
        stored = (token, user)
    }

    public func load() async throws -> (token: Token, user: SessionUser)? {
        stored
    }

    public func clear() async throws {
        stored = nil
    }
}

// MARK: - KeychainCredentialStore<Token>

public final class KeychainCredentialStore<Token: AuthSessionToken>:
    CredentialStore, @unchecked Sendable
{
    private let serviceToken: String
    private let serviceUser:  String
    private let account = "current"
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    /// - Parameter namespace: Reverse-DNS prefix to namespace keychain items.
    ///   Defaults to the main bundle identifier. Override in tests to avoid collisions.
    public init(namespace: String = Bundle.main.bundleIdentifier ?? "com.app") {
        serviceToken = "\(namespace).session.token"
        serviceUser  = "\(namespace).session.user"
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func save(token: Token, user: SessionUser) async throws {
        try keychainSave(try encoder.encode(token), service: serviceToken)
        try keychainSave(try encoder.encode(user),  service: serviceUser)
    }

    public func load() async throws -> (token: Token, user: SessionUser)? {
        guard
            let tokenData = try keychainLoad(service: serviceToken),
            let userData  = try keychainLoad(service: serviceUser)
        else { return nil }

        let token = try decoder.decode(Token.self,       from: tokenData)
        let user  = try decoder.decode(SessionUser.self, from: userData)
        return (token, user)
    }

    public func clear() async throws {
        try keychainDelete(service: serviceToken)
        try keychainDelete(service: serviceUser)
    }

    // MARK: Keychain primitives

    private func keychainSave(_ data: Data, service: String) throws {
        let base: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        SecItemDelete(base as CFDictionary)
        let status = SecItemAdd(
            base.merging([kSecValueData: data]) { $1 } as CFDictionary, nil
        )
        guard status == errSecSuccess else {
            throw SessionError.credentialStoreFailed("Keychain write error: \(status)")
        }
    }

    private func keychainLoad(service: String) throws -> Data? {
        var result: AnyObject?
        let status = SecItemCopyMatching([
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData:  true,
            kSecMatchLimit:  kSecMatchLimitOne
        ] as CFDictionary, &result)

        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw SessionError.credentialStoreFailed("Keychain read error: \(status)")
        }
        return result as? Data
    }

    private func keychainDelete(service: String) throws {
        let status = SecItemDelete([
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SessionError.credentialStoreFailed("Keychain delete error: \(status)")
        }
    }
}
