# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
swift build                                    # Build the library
swift test                                     # Run all tests
swift test --filter UserSessionManagerTests    # Run a single test class
swift test --filter UserSessionManagerTests/test_signIn_withValidCredential_transitionsToSignedIn  # Run a single test
```

Swift 6.0 toolchain required. Targets macOS 10.15+ / iOS 14+. No external dependencies.

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
- **`SessionTokenProviding<Token>`** — Networking layer contract. Single method: `currentValidToken()`. The networking layer has zero knowledge of state, credentials, or users.
- **`SessionManagerEngine`** (internal) — holds all business logic: token refresh, session restore, proactive timer, timeout. Not observable.
- **`UserSessionManager`** — `ObservableObject` wrapper (iOS 14+ / macOS 11+). Use with `@ObservedObject` / `@EnvironmentObject`.
- **`ObservableSessionManager`** — `@Observable` wrapper (iOS 17+ / macOS 14+). Use with `@State` / `@Bindable` / `.environment()`.
- Both wrappers conform to `UserSessionManaging` + `SessionTokenProviding` and delegate to the same engine.

### Token Types

Three concrete `AuthSessionToken` conformers ship out of the box:
- `BearerToken` — OAuth2/JWT (access + refresh + expiry + scopes)
- `OpaqueSessionToken` — single opaque string, optional expiry, no refresh
- `CookieToken` — presence signal only, cookie lives in HTTPCookieStorage

Adding a new token shape requires zero changes to existing code — just conform to `AuthSessionToken`.

### Credential Types

`AuthCredential` protocol with concrete types: `EmailPasswordCredential`, `OAuthCredential`, `AppleCredential`, `PhoneOTPCredential`, `BiometricCredential`, `TokenCredential`. `MultiCredential<A, B>` enum supports providers accepting multiple credential types.

### Type Erasure

- `AnySessionManager<Credential, Token>` — hides Provider/Store generics from SwiftUI views via `@EnvironmentObject`
- `AnyTokenProvider` — erases `SessionTokenProviding<Token>` to a raw string accessor for networking layers

### State Machine

`SessionState` enum: `.loading(AuthOperation)` → `.signedOut` / `.signedIn(SessionUser)` / `.failed(SessionError)` / `.expired`. All derived properties (`isLoading`, `error`, `currentUser`, `isAuthenticated`) come from this single source of truth.

### Configuration

`SessionManagerConfiguration` controls runtime behaviour:
- `proactiveRefreshBuffer` (default: 60s) — how far before expiry to trigger proactive token refresh
- `operationTimeout` (default: 30s) — max wait for provider operations before throwing `.timeout`; `nil` disables

Pass via `UserSessionManager(provider:store:configuration:)` or `ObservableSessionManager(provider:store:configuration:)`.

### Test Approach

Tests use `InMemoryCredentialStore<T>` and mock providers (`MockIdentityProvider` for BearerToken, `MockOpaqueProvider` for OpaqueSessionToken) in `Tests/SessionManagerTests/`. The `MockTokenProvider<Token>` in the main target supports networking-layer unit tests without any session manager dependency. Tests also cover `KeychainCredentialStore` round-trips, operation timeout, proactive refresh timer, operation deduplication, and `MultiCredential` flows.
