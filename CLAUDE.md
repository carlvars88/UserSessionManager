# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
swift build                                    # Build the library
swift test                                     # Run all tests
swift test --filter UserSessionManagerTests    # Run a single test class
swift test --filter UserSessionManagerTests/test_signIn_withValidCredential_transitionsToSignedIn  # Run a single test
```

Swift 6.0 toolchain required. Targets macOS 12+ / iOS 16+. No external dependencies.

## Architecture

This is a Swift Package (`SessionManager`) providing a generic, protocol-driven session management library for iOS/macOS apps. The core design separates **what goes in** (credentials) from **what comes out** (tokens) using two associated types on `IdentityProvider`.

### Key Generic Constraint

The entire system pivots on one compile-time constraint:

```
UserSessionManager<Provider, Store> where Store.Token == Provider.Token
```

This ensures the credential store and identity provider agree on the token type. Mismatches are build errors, not runtime crashes.

### Protocol Roles (Two Callers, One Engine, Two Wrappers)

- **`UserSessionManaging<Provider, Store>`** — UI layer contract. Owns the `SessionState` state machine and auth commands (signIn, signOut, reauthenticate, updateUser).
- **`SessionTokenProviding<Token>`** — Networking layer contract (`AnyObject`). Single method: `currentValidToken()`. The networking layer has zero knowledge of state, credentials, or users.
- **`SessionManagerEngine`** (internal) — holds all business logic: token refresh, session restore, proactive timer, timeout, operation deduplication. Not observable. Wrappers call `tearDown()` from `deinit` to cancel in-flight tasks.
- **`UserSessionManager`** — `ObservableObject` wrapper (iOS 16+ / macOS 12+). Use with `@ObservedObject` / `@EnvironmentObject`.
- **`ObservableSessionManager`** — `@Observable` wrapper (iOS 17+ / macOS 14+). Conditionally compiled via `#if canImport(Observation)`. Use with `@State` / `@Bindable` / `.environment()`.
- Both wrappers conform to `UserSessionManaging` + `SessionTokenProviding` and delegate to the same engine.

### Token Types

Three concrete `AuthSessionToken` conformers ship out of the box:
- `BearerToken` — OAuth2/JWT (access + refresh + expiry + scopes)
- `OpaqueSessionToken` — single opaque string, optional expiry, no refresh
- `CookieToken` — presence signal only, cookie lives in HTTPCookieStorage

`AuthSessionToken` requires only `isExpired: Bool` and `expiresAt: Date?`. The proactive refresh threshold is owned entirely by `SessionManagerConfiguration.proactiveRefreshBuffer` — token types do not encode a threshold. Adding a new token shape requires zero changes to existing code.

### Credential Types

`AuthCredential` protocol with concrete types: `EmailPasswordCredential`, `OAuthCredential`, `AppleCredential`, `PhoneOTPCredential`, `BiometricCredential`, `TokenCredential`.

### Type Erasure

- `AnyTokenProvider` — erases `SessionTokenProviding<Token>` to a raw string accessor for networking layers

The recommended pattern for hiding `UserSessionManager` generics from SwiftUI views is a `typealias` at the app level:
```swift
typealias AppSession = UserSessionManager<MyProvider, KeychainCredentialStore<BearerToken>>
```

### State Machine

`SessionState` enum: `.loading(AuthOperation)` → `.signedOut` / `.signedIn(SessionUser)` / `.failed(SessionError)` / `.expired`. All derived properties (`isLoading`, `error`, `currentUser`, `isAuthenticated`) come from this single source of truth.

### Configuration

`SessionManagerConfiguration` controls runtime behaviour:
- `proactiveRefreshBuffer` (default: 60s) — how far before expiry to trigger proactive token refresh. This is the sole threshold used by the engine; token types do not duplicate it.
- `operationTimeout` (default: 30s) — max wait for provider operations before throwing `.timeout`; `nil` disables
- `logLevel` (default: `.info`) — minimum log level emitted; messages below this are dropped before reaching the logger
- `logger` (default: `OSLogger`) — pluggable `any SessionLogger` backend; swap to `PrintLogger` in tests or forward to Datadog/Sentry/SwiftLog

Pass via `UserSessionManager(provider:store:configuration:)` or `ObservableSessionManager(provider:store:configuration:)`.

### Logging

`SessionLogger` is a plain protocol (no associated types) usable as `any SessionLogger`. Two built-in backends:
- `OSLogger` — backed by `os.log`, default in production
- `PrintLogger` — writes to stdout, useful in tests

The engine pre-filters by `logLevel` before calling the logger, so backends do not need to repeat the threshold check.

### Session Restore

On init, the engine runs `restoreSession()` in a background task. It follows a three-stage fallback:

1. **Provider-native cache** — calls `provider.currentToken()`. If a token is returned and a stored user exists, restore succeeds immediately. If the token exists but no stored user is found, a silent `refreshToken()` is attempted to recover user info.
2. **Credential store** — loads the stored token. If valid, restores the session directly. If expired, attempts a silent `refreshToken()`.
3. **Signed out** — if neither path succeeds, transitions to `.signedOut`.

All public methods (`signIn`, `signOut`, `reauthenticate`, `currentValidToken`) await the restore task before proceeding.

### Operation Ordering

`signOut` **waits for** any in-flight `signIn` or `reauthenticate` to complete before proceeding — it does not cancel them. Rationale: the provider may have already issued tokens server-side before cancellation could reach it, leaving tokens that can no longer be revoked. By waiting, `signOut` always has a valid token to revoke.

Concurrent `currentValidToken()` calls are deduplicated via `ongoingRefreshTask`: only one refresh runs at a time; all concurrent callers await the same task.

### Refresh Failure Classification

Token refresh errors are classified as **permanent** or **transient**:
- `invalidCredentials` — permanent; the server explicitly rejected the token. Transitions to `.expired` and clears the credential store.
- All other errors (`.timeout`, `.providerError`, etc.) — transient; state stays `.signedIn` and the store is preserved so the next `currentValidToken()` call can retry without forcing re-login.

The same classification applies during session restore on app launch.

### Test Approach

Tests use `InMemoryCredentialStore<T>` (an actor) and mock providers (`MockIdentityProvider` for BearerToken, `MockOpaqueProvider` for OpaqueSessionToken) in `Tests/SessionManagerTests/`. `MockTokenProvider<Token>` is also in the test target for networking-layer unit tests without any session manager dependency.

`MockIdentityProvider` accepts a `refreshError: SessionError` parameter (default `.invalidCredentials`) to control whether a simulated refresh failure is permanent or transient.

`KeychainCredentialStore<Token>` stores credentials atomically under `"{namespace}.session"`. It automatically migrates from a legacy two-entry format (`"{namespace}.session.token"` + `"{namespace}.session.user"`) on first load.

Tests cover: `KeychainCredentialStore` round-trips and legacy migration, operation timeout, proactive refresh timer, operation deduplication, permanent vs transient refresh failure (runtime and restore), and session restore with expired tokens.
