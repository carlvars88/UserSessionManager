# SessionManager

A generic, protocol-driven session management library for iOS and macOS. No external dependencies.

- **Compile-time safety** — credential and token types are enforced at the call site; mismatches are build errors
- **Two-caller design** — UI layer and networking layer each get a minimal, purpose-built interface
- **Three token shapes** out of the box: OAuth2 bearer, opaque session token, cookie-based
- **Automatic token refresh** — proactive refresh timer, one-flight deduplication, transient vs permanent failure classification
- **Pluggable everything** — identity provider, credential store, logger

---

## Requirements

- Swift 6.0+
- iOS 16+ / macOS 12+

---

## Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/your-org/SessionManager.git", from: "1.0.0")
],
targets: [
    .target(
        name: "MyApp",
        dependencies: ["SessionManager"]
    )
]
```

---

## Quick Start

### 1. Implement `IdentityProvider`

```swift
final class MyAuthProvider: IdentityProvider, Sendable {
    typealias Credential = EmailPasswordCredential
    typealias Token      = BearerToken

    let providerID = "my-backend"

    func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
        let response = try await api.login(email: credential.email, password: credential.password)
        return AuthResult(
            user:  SessionUser(id: response.userID, displayName: response.name, email: response.email),
            token: BearerToken(accessToken: response.accessToken,
                               refreshToken: response.refreshToken,
                               expiresAt: response.expiresAt)
        )
    }

    func refreshToken(_ token: BearerToken) async throws -> AuthResult<BearerToken> {
        guard let refresh = token.refreshToken else { throw SessionError.tokenRefreshFailed }
        let response = try await api.refresh(refreshToken: refresh)
        return AuthResult(
            user:  SessionUser(id: response.userID, displayName: response.name),
            token: BearerToken(accessToken: response.accessToken,
                               refreshToken: response.refreshToken,
                               expiresAt: response.expiresAt)
        )
    }

    func signOut(token: BearerToken) async throws {
        try await api.logout(accessToken: token.accessToken)
    }
}
```

### 2. Create the manager

```swift
// ObservableObject (iOS 16+)
let session = UserSessionManager(
    provider: MyAuthProvider(),
    store:    KeychainCredentialStore<BearerToken>()
)

// @Observable (iOS 17+)
let session = ObservableSessionManager(
    provider: MyAuthProvider(),
    store:    KeychainCredentialStore<BearerToken>()
)
```

### 3. Use in SwiftUI

```swift
@main
struct MyApp: App {
    @StateObject private var session = UserSessionManager(
        provider: MyAuthProvider(),
        store:    KeychainCredentialStore<BearerToken>()
    )

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(session)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var session: UserSessionManager<MyAuthProvider, KeychainCredentialStore<BearerToken>>

    var body: some View {
        switch session.state {
        case .loading:         ProgressView()
        case .signedOut:       SignInView()
        case .signedIn(let u): HomeView(user: u)
        case .failed(let e):   ErrorView(error: e)
        case .expired:         SignInView()
        }
    }
}
```

### 4. Inject into your networking layer

```swift
struct APIClient {
    let tokens: AnyTokenProvider

    func request(_ url: URL) async throws -> Data {
        var req = URLRequest(url: url)
        if let token = try await tokens.currentRawToken() {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return try await URLSession.shared.data(for: req).0
    }
}

// Wiring
let client = APIClient(tokens: AnyTokenProvider(session))
```

---

## Architecture

### The Core Constraint

```
UserSessionManager<Provider, Store> where Store.Token == Provider.Token
```

The credential store and identity provider must agree on the token type. A `KeychainCredentialStore<BearerToken>` paired with a provider that returns `OpaqueSessionToken` is a **build error**, not a runtime crash.

### Two Callers, One Engine

```
UI Layer          → UserSessionManaging   → state, signIn, signOut, reauthenticate, updateUser
Networking Layer  → SessionTokenProviding → currentValidToken()
```

The networking layer has zero knowledge of state, credentials, or users. It only calls `currentValidToken()` — the engine handles refresh transparently.

### State Machine

```
.loading(.restoringSession)   ← initial, on app launch
.loading(.signingIn)
.loading(.signingOut)
.loading(.reauthenticating)
.signedOut
.signedIn(SessionUser)
.failed(SessionError)
.expired                      ← refresh token permanently rejected
```

All derived properties (`isLoading`, `isAuthenticated`, `currentUser`, `error`) are computed from this single source of truth.

---

## Token Types

### `BearerToken` — OAuth2 / JWT

```swift
BearerToken(
    accessToken:  "eyJ...",
    refreshToken: "dGVz...",   // optional
    expiresAt:    Date(...),   // optional
    tokenType:    "Bearer",    // default
    scopes:       ["read", "write"]
)
```

### `OpaqueSessionToken` — Custom backends

```swift
OpaqueSessionToken(value: "sess_abc123", expiresAt: Date(...))
```

No refresh token — expiry causes a full re-login.

### `CookieToken` — Cookie-based sessions

```swift
CookieToken(cookieName: "session_id", expiresAt: Date(...))
```

No token data held in-process. The manager treats this as a presence signal; the actual cookie lives in `HTTPCookieStorage`.

### Custom token types

Conform to `AuthSessionToken`:

```swift
public protocol AuthSessionToken: Sendable, Codable, Equatable {
    var isExpired: Bool  { get }
    var expiresAt: Date? { get }
}
```

---

## Credential Types

| Type | Fields |
|------|--------|
| `EmailPasswordCredential` | `email`, `password` |
| `OAuthCredential` | `provider`, `idToken`, `accessToken?`, `nonce?` |
| `AppleCredential` | `userIdentifier`, `identityToken`, `authorizationCode`, `fullName?`, `email?` |
| `PhoneOTPCredential` | `phoneNumber`, `otp`, `verificationID` |
| `BiometricCredential` | `localizedReason` |
| `TokenCredential` | `rawToken`, `provider` |

For providers that accept more than one credential type:

```swift
typealias Credential = MultiCredential<EmailPasswordCredential, OAuthCredential>

// Sign in with either
await session.signIn(with: .first(EmailPasswordCredential(email: "a@b.com", password: "pass")))
await session.signIn(with: .second(OAuthCredential(provider: "google", idToken: "tok")))
```

---

## Configuration

```swift
let config = SessionManagerConfiguration(
    proactiveRefreshBuffer: 60,    // refresh this many seconds before expiry (default: 60)
    operationTimeout:       30,    // max seconds per provider operation; nil = no limit (default: 30)
    logLevel:               .info, // minimum level emitted (default: .info)
    logger:                 OSLogger()  // default: os.log backend
)

let session = UserSessionManager(provider: ..., store: ..., configuration: config)
```

### Proactive Refresh

The engine schedules a timer to refresh the token `proactiveRefreshBuffer` seconds before expiry. When `currentValidToken()` is called while a refresh is already in flight, all concurrent callers await the same task — only one network request is made.

### Refresh Failure Behaviour

| Error | Meaning | Engine behaviour |
|-------|---------|-----------------|
| `invalidCredentials` | Server explicitly rejected the token | Clears store, transitions to `.expired` |
| Any other error | Transient (network, timeout, 5xx) | Preserves store and state; next call retries |

---

## Simplifying generic types in SwiftUI

`UserSessionManager` carries two generic parameters. Define a `typealias` once at the app level to keep view code concise:

```swift
// AppSession.swift
typealias AppSession = UserSessionManager<MyProvider, KeychainCredentialStore<BearerToken>>

// MyApp.swift
@StateObject private var session = AppSession(provider: MyProvider(),
                                              store: KeychainCredentialStore())
RootView().environmentObject(session)

// Any view
@EnvironmentObject var session: AppSession
```

## Type Erasure

### `AnyTokenProvider` — hide token type from networking

```swift
// Convenience init — picks the right raw value automatically
let tokens = AnyTokenProvider(session)   // BearerToken → accessToken string

// Custom extraction
let tokens = AnyTokenProvider(session) { token in token.accessToken }
```

---

## OAuth2 Provider

The `IdentityProviders` target ships a ready-to-use OAuth2 Authorization Code + PKCE provider (RFC 6749 / RFC 7636) built on plain `URLSession`:

```swift
import IdentityProviders

let provider = OAuth2Provider(
    configuration: .init(
        clientID:           "your-client-id",
        tokenEndpoint:      URL(string: "https://auth.example.com/oauth/token")!,
        revocationEndpoint: URL(string: "https://auth.example.com/oauth/revoke")!,
        userInfoEndpoint:   URL(string: "https://auth.example.com/userinfo")!,
        redirectURI:        "myapp://callback"
    )
)

let session = UserSessionManager(
    provider: provider,
    store:    KeychainCredentialStore<BearerToken>()
)
```

Sign in with the authorization code from your UI flow (`ASWebAuthenticationSession`, etc.):

```swift
let credential = OAuthCredential(
    provider:    "my-server",
    idToken:     authorizationCode,   // the code, not a JWT
    nonce:       codeVerifier         // PKCE code_verifier
)
await session.signIn(with: credential)
```

Works with any RFC-compliant server: Auth0, Okta, Keycloak, Azure AD, and custom servers.

---

## Logging

```swift
// Default — os.log (visible in Console.app and Xcode)
logger: OSLogger(subsystem: "com.myapp", category: "Auth")

// Stdout — useful in tests
logger: PrintLogger(minLevel: .debug)

// Custom — forward to Datadog, Sentry, SwiftLog, etc.
struct DatadogLogger: SessionLogger {
    func log(level: LogLevel, _ message: @autoclosure () -> String,
             file: String, function: String, line: UInt) {
        Datadog.logger.log(level: level.ddLevel, message: message())
    }
}
```

Log levels: `.trace` `.debug` `.info` `.notice` `.warning` `.error` `.fault`

---

## Credential Stores

### `KeychainCredentialStore<Token>` — production

Stores credentials atomically in the system Keychain. Automatically migrates from a previous two-entry format if present.

```swift
KeychainCredentialStore<BearerToken>()
// or with a custom namespace (useful in tests):
KeychainCredentialStore<BearerToken>(namespace: "com.myapp.auth")
```

### `InMemoryCredentialStore<Token>` — testing

Actor-isolated, no persistence. Session is lost when the process exits.

```swift
InMemoryCredentialStore<BearerToken>()
```

---

## Testing

The `SessionManager` module is designed to be testable without mocking the framework itself — implement `IdentityProvider` and pair it with `InMemoryCredentialStore`.

```swift
final class MockProvider: IdentityProvider, Sendable {
    typealias Credential = EmailPasswordCredential
    typealias Token      = BearerToken
    let providerID = "mock"

    func signIn(with credential: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
        guard credential.email.contains("@") else { throw SessionError.invalidCredentials }
        return AuthResult(
            user:  SessionUser(id: "u1", displayName: "Test User"),
            token: BearerToken(accessToken: "test-token", expiresAt: Date().addingTimeInterval(3600))
        )
    }

    func refreshToken(_ token: BearerToken) async throws -> AuthResult<BearerToken> { ... }
    func signOut(token: BearerToken) async throws {}
}

// In your test
let sut = UserSessionManager(provider: MockProvider(), store: InMemoryCredentialStore<BearerToken>())
await sut.signIn(with: EmailPasswordCredential(email: "a@b.com", password: "password"))
XCTAssertTrue(sut.state.isAuthenticated)
```

For networking-layer tests that need a token provider but no full session manager:

```swift
// MockTokenProvider<Token> — no session manager needed
let provider = MockTokenProvider<BearerToken>(.success(BearerToken(accessToken: "tok")))
let token = try await provider.currentValidToken()
```

---

## License

MIT
