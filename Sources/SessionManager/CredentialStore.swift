// MARK: - Protocols/CredentialStore.swift
//
// CredentialStore is generic over Token.
//
// The constraint `Store.Token == Provider.Token` on UserSessionManager guarantees
// at compile time that a store built for BearerToken cannot be paired with a
// provider that produces OpaqueSessionToken. No runtime cast, no force-unwrap.

import Foundation
import Security

// MARK: - CredentialStore Protocol

/// Persistence contract for session tokens and user profiles.
///
/// The session manager calls `save`, `load`, and `clear` automatically —
/// you do not call them directly. Implement this protocol to add a custom
/// storage backend (e.g. encrypted file, SQLite, group container).
///
/// The `Token` associated type must match the `Token` of the paired
/// `IdentityProvider` — a mismatch is a compile-time error.
public protocol CredentialStore: Sendable {

    /// The token shape this store persists. Must equal `IdentityProvider.Token`.
    associatedtype Token: AuthSessionToken

    /// Persist a token and its associated user profile atomically.
    func save(token: Token, user: SessionUser) async throws

    /// Load the persisted token and user profile, or `nil` if none exists.
    func load() async throws -> (token: Token, user: SessionUser)?

    /// Remove all persisted credentials.
    func clear() async throws
}

// MARK: - InMemoryCredentialStore

/// An in-memory credential store backed by a single actor-isolated variable.
///
/// Credentials are lost when the process exits. Use this store in unit tests
/// and SwiftUI previews — never in production.
///
/// ```swift
/// let sut = UserSessionManager(
///     provider: MockProvider(),
///     store:    InMemoryCredentialStore<BearerToken>()
/// )
/// ```
public actor InMemoryCredentialStore<Token: AuthSessionToken>: CredentialStore {

    private var stored: (token: Token, user: SessionUser)?

    public init() {}

    public func save(token: Token, user: SessionUser) throws {
        stored = (token, user)
    }

    public func load() throws -> (token: Token, user: SessionUser)? {
        stored
    }

    public func clear() throws {
        stored = nil
    }
}

// MARK: - KeychainCredentialStore

/// A production credential store that persists tokens in the system Keychain.
///
/// Token and user are encoded together as a single JSON blob under the key
/// `"{namespace}.session"`, making the write atomic with respect to
/// Keychain semantics (delete-then-add). Automatically migrates from a
/// legacy two-entry format (`"{namespace}.session.token"` +
/// `"{namespace}.session.user"`) if detected on first load.
///
/// ```swift
/// // Default namespace (bundle identifier)
/// KeychainCredentialStore<BearerToken>()
///
/// // Custom namespace — useful in tests to avoid collisions
/// KeychainCredentialStore<BearerToken>(namespace: "com.myapp.auth.test")
///
/// // Background-capable app (widgets, background fetch)
/// KeychainCredentialStore<BearerToken>(accessibility: kSecAttrAccessibleAfterFirstUnlock)
/// ```
public actor KeychainCredentialStore<Token: AuthSessionToken>: CredentialStore {
    private let serviceSession: String
    // Legacy keys for migration from two-entry format
    private let legacyServiceToken: String
    private let legacyServiceUser:  String
    private let account:       String = "current"
    private let accessibility: CFString
    private let encoder:       JSONEncoder
    private let decoder:       JSONDecoder
    // Dedicated serial queue for blocking SecItem* calls. Using a queue frees
    // the cooperative thread pool while the Keychain I/O is in progress.
    private nonisolated let keychainQueue = DispatchQueue(
        label: "com.sessionmanager.keychain",
        qos: .userInitiated
    )

    private struct StoredSession: Codable {
        let token: Token
        let user: SessionUser
    }

    /// Creates a `KeychainCredentialStore`.
    ///
    /// - Parameters:
    ///   - namespace: Reverse-DNS prefix used to namespace Keychain items.
    ///     Defaults to the main bundle identifier. Override in tests to
    ///     prevent collisions between test runs.
    ///   - accessibility: When the Keychain item can be read. Defaults to
    ///     `kSecAttrAccessibleWhenUnlocked` (device must be unlocked).
    ///     Use `kSecAttrAccessibleAfterFirstUnlock` for apps that read
    ///     credentials in background contexts (push extensions, background
    ///     fetch, widgets).
    ///   - encoder: JSON encoder for serialising credentials.
    ///     Defaults to ISO 8601 date encoding.
    ///   - decoder: JSON decoder for deserialising credentials.
    ///     Defaults to ISO 8601 date decoding.
    public init(
        namespace:     String     = Bundle.main.bundleIdentifier ?? "com.app",
        accessibility: CFString   = kSecAttrAccessibleWhenUnlocked,
        encoder:       JSONEncoder = {
            let e = JSONEncoder()
            e.dateEncodingStrategy = .iso8601
            return e
        }(),
        decoder:       JSONDecoder = {
            let d = JSONDecoder()
            d.dateDecodingStrategy = .iso8601
            return d
        }()
    ) {
        serviceSession      = "\(namespace).session"
        legacyServiceToken  = "\(namespace).session.token"
        legacyServiceUser   = "\(namespace).session.user"
        self.accessibility  = accessibility
        self.encoder        = encoder
        self.decoder        = decoder
    }

    public func save(token: Token, user: SessionUser) async throws {
        let session = StoredSession(token: token, user: user)
        try await keychainSave(try encoder.encode(session), service: serviceSession)
    }

    public func load() async throws -> (token: Token, user: SessionUser)? {
        // Try atomic format first
        if let data = try await keychainLoad(service: serviceSession) {
            let session = try decoder.decode(StoredSession.self, from: data)
            return (session.token, session.user)
        }
        // Migrate from legacy two-entry format
        guard
            let tokenData = try await keychainLoad(service: legacyServiceToken),
            let userData  = try await keychainLoad(service: legacyServiceUser)
        else { return nil }
        let token = try decoder.decode(Token.self,       from: tokenData)
        let user  = try decoder.decode(SessionUser.self, from: userData)
        // Persist in new format and clean up legacy entries
        try await save(token: token, user: user)
        try? await keychainDelete(service: legacyServiceToken)
        try? await keychainDelete(service: legacyServiceUser)
        return (token, user)
    }

    public func clear() async throws {
        try await keychainDelete(service: serviceSession)
        // Clean up legacy entries if they exist
        try? await keychainDelete(service: legacyServiceToken)
        try? await keychainDelete(service: legacyServiceUser)
    }

    // MARK: Keychain primitives
    //
    // Each primitive captures the values it needs from the actor, then dispatches
    // the blocking SecItem* call onto keychainQueue via a checked continuation.
    // This frees the cooperative thread pool thread while the Keychain I/O runs.

    private func keychainSave(_ data: Data, service: String) async throws {
        let account       = account
        let accessibility = accessibility
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            keychainQueue.async {
                let base: [CFString: Any] = [
                    kSecClass:       kSecClassGenericPassword,
                    kSecAttrService: service,
                    kSecAttrAccount: account
                ]
                SecItemDelete(base as CFDictionary)
                let status = SecItemAdd(
                    base.merging([kSecValueData: data, kSecAttrAccessible: accessibility]) { $1 } as CFDictionary, nil
                )
                if status == errSecSuccess {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: SessionError.credentialStoreFailed("Keychain write error: \(status)"))
                }
            }
        }
    }

    private func keychainLoad(service: String) async throws -> Data? {
        let account = account
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            keychainQueue.async {
                var result: AnyObject?
                let status = SecItemCopyMatching([
                    kSecClass:       kSecClassGenericPassword,
                    kSecAttrService: service,
                    kSecAttrAccount: account,
                    kSecReturnData:  true,
                    kSecMatchLimit:  kSecMatchLimitOne
                ] as CFDictionary, &result)

                if status == errSecItemNotFound {
                    continuation.resume(returning: nil)
                } else if status == errSecSuccess {
                    continuation.resume(returning: result as? Data)
                } else {
                    continuation.resume(throwing: SessionError.credentialStoreFailed("Keychain read error: \(status)"))
                }
            }
        }
    }

    private func keychainDelete(service: String) async throws {
        let account = account
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            keychainQueue.async {
                let status = SecItemDelete([
                    kSecClass:       kSecClassGenericPassword,
                    kSecAttrService: service,
                    kSecAttrAccount: account
                ] as CFDictionary)
                if status == errSecSuccess || status == errSecItemNotFound {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: SessionError.credentialStoreFailed("Keychain delete error: \(status)"))
                }
            }
        }
    }
}
