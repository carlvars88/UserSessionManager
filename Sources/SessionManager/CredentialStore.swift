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

    /// Remove only the persisted token, preserving the user profile.
    ///
    /// Called by the session manager on a permanent token refresh failure
    /// (e.g. `invalidCredentials`). The user profile — including any provider
    /// metadata such as a `deviceAuthCookie` — survives so it can be reused
    /// on the next sign-in without forcing the user through setup steps again.
    ///
    /// The default implementation calls `clear()`, removing everything.
    /// Override to provide split token/user lifecycle.
    func clearToken() async throws

    /// Remove all persisted credentials (token and user profile).
    ///
    /// Called on explicit sign-out. After this call `load()` returns `nil`.
    func clear() async throws
}

public extension CredentialStore {
    /// Default: delegates to `clear()`. Override for split token/user lifecycle.
    func clearToken() async throws { try await clear() }
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

    private var storedToken: Token?
    private var storedUser:  SessionUser?

    public init() {}

    public func save(token: Token, user: SessionUser) throws {
        storedToken = token
        storedUser  = user
    }

    public func load() throws -> (token: Token, user: SessionUser)? {
        guard let token = storedToken, let user = storedUser else { return nil }
        return (token, user)
    }

    /// Clears only the token. The user profile is preserved for the next sign-in.
    public func clearToken() throws {
        storedToken = nil
    }

    public func clear() throws {
        storedToken = nil
        storedUser  = nil
    }
}

// MARK: - KeychainCredentialStore

/// A production credential store that persists tokens in the system Keychain.
///
/// Token and user are stored under **separate** Keychain keys:
///   - `"{namespace}.session.token"` — cleared by `clearToken()` and `clear()`
///   - `"{namespace}.session.user"`  — cleared only by `clear()` (explicit sign-out)
///
/// This split lifecycle means a permanent token refresh failure (e.g. `invalid_grant`)
/// transitions the session to `.expired` without wiping the user profile. Provider
/// metadata stored in `SessionUser.metadata` — such as a trusted-device cookie —
/// therefore survives token expiry and is available on the next sign-in.
///
/// Automatically migrates from the previous single-blob format
/// (`"{namespace}.session"`) on first load.
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
    private let serviceToken: String    // "{namespace}.session.token"
    private let serviceUser:  String    // "{namespace}.session.user"
    private let serviceLegacyBlob: String  // "{namespace}.session" — migration source only
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

    // Used only when migrating from the legacy single-blob format.
    private struct LegacyStoredSession: Codable {
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
        serviceToken      = "\(namespace).session.token"
        serviceUser       = "\(namespace).session.user"
        serviceLegacyBlob = "\(namespace).session"
        self.accessibility  = accessibility
        self.encoder        = encoder
        self.decoder        = decoder
    }

    public func save(token: Token, user: SessionUser) async throws {
        try await keychainSave(try encoder.encode(token), service: serviceToken)
        try await keychainSave(try encoder.encode(user),  service: serviceUser)
    }

    public func load() async throws -> (token: Token, user: SessionUser)? {
        // Current split format: both keys must exist.
        if let tokenData = try await keychainLoad(service: serviceToken),
           let userData  = try await keychainLoad(service: serviceUser) {
            let token = try decoder.decode(Token.self,       from: tokenData)
            let user  = try decoder.decode(SessionUser.self, from: userData)
            return (token, user)
        }

        // Migrate from previous single-blob format ("{namespace}.session").
        if let blobData = try await keychainLoad(service: serviceLegacyBlob) {
            let legacy = try decoder.decode(LegacyStoredSession.self, from: blobData)
            try await save(token: legacy.token, user: legacy.user)
            try? await keychainDelete(service: serviceLegacyBlob)
            return (legacy.token, legacy.user)
        }

        return nil
    }

    /// Removes only the token key. The user profile key is preserved so
    /// `SessionUser.metadata` (e.g. a trusted-device cookie) survives token expiry.
    public func clearToken() async throws {
        try await keychainDelete(service: serviceToken)
    }

    public func clear() async throws {
        try await keychainDelete(service: serviceToken)
        try await keychainDelete(service: serviceUser)
        // Clean up legacy blob if present (e.g. migration was never triggered)
        try? await keychainDelete(service: serviceLegacyBlob)
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
