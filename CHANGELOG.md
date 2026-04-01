# Changelog

All notable changes to this project will be documented in this file.
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] - 2026-04-01

Initial production release.

### Core library (`SessionManager`)

- Generic, protocol-driven session management for iOS 16+ / macOS 12+
- `UserSessionManager` — `ObservableObject` wrapper for `@StateObject` / `@EnvironmentObject`
- `ObservableSessionManager` — `@Observable` wrapper for `@State` / `@Bindable` (iOS 17+ / macOS 14+)
- `SessionManagerEngine` — internal engine shared by both wrappers; owns all business logic
- `UserSessionManaging` — UI-layer protocol (`@MainActor`): state machine + auth commands
- `SessionTokenProviding` — networking-layer protocol (`@MainActor`): `currentValidToken()` + `forceRefreshToken()`
- `AnyTokenProvider` — type-erases `SessionTokenProviding` to a raw string accessor

#### State machine
`SessionState` with `.loading`, `.signedOut`, `.signedIn`, `.failed`, `.expired`

#### Token types
- `BearerToken` — OAuth2 / JWT (access + refresh + expiry + scopes)
- `OpaqueSessionToken` — single opaque string, optional expiry
- `CookieToken` — presence signal; cookie lives in `HTTPCookieStorage`

#### Credential types
`EmailPasswordCredential`, `OAuthCredential`, `AppleCredential`, `PhoneOTPCredential`, `BiometricCredential`, `TokenCredential`

#### Session management features
- Session restore on app launch (provider-native cache → credential store → signed out)
- Proactive token refresh timer (`proactiveRefreshBuffer`, default 60 s)
- One-flight refresh deduplication — concurrent `currentValidToken()` calls join the same task
- `forceRefreshToken()` — bypasses local expiry check; use on server-side 401 rejections
- Permanent vs transient refresh failure classification (`invalidCredentials` = permanent → `.expired`)
- `refreshUser()` — explicit caller-controlled profile refresh without a full sign-in cycle
- Operation ordering: `signOut` waits for in-flight `signIn`/`reauthenticate` before proceeding
- Configurable operation timeout (`operationTimeout`, default 30 s; `nil` = unlimited)

#### Storage
- `KeychainCredentialStore<Token>` — atomic Keychain storage; `SecItem*` calls on a dedicated serial queue; configurable `kSecAttrAccessible`
- `InMemoryCredentialStore<Token>` — actor-isolated, no persistence; use in tests

#### Logging
- `SessionLogger` protocol — pluggable backend
- `OSLogger` — `os.log` backend (default)
- `PrintLogger` — stdout backend for tests

#### Swift 6 concurrency
- `@MainActor` on both protocols; no `@preconcurrency` suppressions
- All public types are `Sendable`

### Identity Providers (`IdentityProviders`)

- `OAuth2Provider` — Authorization Code + PKCE (RFC 6749 / RFC 7636) on plain `URLSession`; works with Auth0, Okta, Keycloak, Azure AD, and custom servers
- `FirebaseProvider` — Firebase Authentication with `FirebaseCredential` enum (`.emailPassword`, `.apple`, `.google`, `.oauth`, `.phoneOTP`, `.anonymous`); conditionally compiled via `#if canImport(FirebaseAuth)`

### Tests

71 tests covering: sign-in / sign-out flows, session restore, token refresh (proactive, on-demand, forced), operation deduplication, permanent vs transient failure, `forceRefreshToken` on valid tokens, `refreshUser`, `KeychainCredentialStore` round-trips and legacy migration, operation timeout, `AnyTokenProvider`, `MockTokenProvider`
