// MARK: - ObservableExample.swift
//
// SwiftUI example using ObservableSessionManager (@Observable).
// Requires iOS 17+ / macOS 14+.
//
// Wiring:
//
//   @main
//   struct MyApp: App {
//       @State private var session = ObservableSessionManager(
//           provider: MyProvider(),
//           store:    KeychainCredentialStore<BearerToken>()
//       )
//       var body: some Scene {
//           WindowGroup {
//               ObservableRootView().environment(session)
//           }
//       }
//   }
//
// Key differences from the ObservableObject variant:
//   - Fine-grained invalidation: a view reading only `state.currentUser`
//     does NOT re-render when `state.isLoading` changes.
//   - Use .environment() / @Environment instead of .environmentObject / @EnvironmentObject.
//   - No need for AnySessionManager in most cases — just inject the concrete type.
//     Define a typealias to keep view signatures short:
//
//       typealias AppSession = ObservableSessionManager<OAuth2Provider, KeychainCredentialStore<BearerToken>>

#if canImport(SwiftUI) && canImport(Observation)
import SwiftUI
import Observation
import SessionManager

// MARK: - iOS-only text field modifier helpers

@available(macOS 14.0, iOS 17.0, *)
private extension View {
    func emailFieldHints() -> some View {
        #if os(iOS)
        self.textContentType(.emailAddress).textInputAutocapitalization(.never)
        #else
        self
        #endif
    }
    func passwordFieldHint() -> some View {
        #if os(iOS)
        self.textContentType(.password)
        #else
        self
        #endif
    }
}

// MARK: - Convenience Typealias (replace with your real provider/store)

@available(iOS 17.0, macOS 14.0, *)
typealias ExampleSession = ObservableSessionManager<ExampleIdentityProvider, InMemoryCredentialStore<BearerToken>>

// MARK: - Root View

@available(iOS 17.0, macOS 14.0, *)
public struct ObservableRootView: View {

    @Environment(ExampleSession.self) var session

    public init() {}

    public var body: some View {
        Group {
            switch session.state {
            case .loading:
                ProgressView("Restoring session…")
            case .signedOut, .failed, .expired(_):
                ObservableSignInView()
            case .signedIn:
                ObservableHomeView()
            }
        }
        .animation(.default, value: session.state)
    }
}

// MARK: - Sign-In View

@available(iOS 17.0, macOS 14.0, *)
public struct ObservableSignInView: View {

    @Environment(ExampleSession.self) var session

    @State private var email    = ""
    @State private var password = ""

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                Section("Credentials") {
                    TextField("Email", text: $email)
                        .emailFieldHints()
                    SecureField("Password", text: $password)
                        .passwordFieldHint()
                }

                if let error = session.state.error {
                    Section {
                        Text(error.localizedDescription)
                            .foregroundStyle(.red)
                    }
                }

                if session.state.isExpired {
                    Section {
                        Text("Your session expired. Please sign in again.")
                            .foregroundStyle(.orange)
                    }
                }

                Section {
                    Button {
                        Task {
                            await session.signIn(
                                with: EmailPasswordCredential(email: email, password: password)
                            )
                        }
                    } label: {
                        if session.state.isLoading {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Sign In").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(session.state.isLoading || email.isEmpty || password.isEmpty)
                }
            }
            .navigationTitle("Sign In")
        }
    }
}

// MARK: - Home View

@available(iOS 17.0, macOS 14.0, *)
public struct ObservableHomeView: View {

    @Environment(ExampleSession.self) var session

    public init() {}

    public var body: some View {
        NavigationStack {
            List {
                if let user = session.state.currentUser {
                    Section("Account") {
                        LabeledContent("Name",  value: user.displayName)
                        LabeledContent("Email", value: user.email ?? "—")
                        LabeledContent("ID",    value: user.id)
                    }
                }

                Section {
                    Button("Sign Out", role: .destructive) {
                        Task { await session.signOut() }
                    }
                    .disabled(session.state.isLoading)
                }
            }
            .navigationTitle("Home")
        }
    }
}

// MARK: - Reauthentication Example
//
// Gate a sensitive action behind re-authentication without signing the user out.

@available(iOS 17.0, macOS 14.0, *)
struct ReauthenticateBeforeDeleteView: View {

    @Environment(ExampleSession.self) var session
    @State private var password = ""
    @State private var authError: Error?

    var body: some View {
        Form {
            Section("Confirm identity to delete your account") {
                SecureField("Password", text: $password)
                    .passwordFieldHint()
            }

            if let authError {
                Section {
                    Text(authError.localizedDescription)
                        .foregroundStyle(.red)
                }
            }

            Section {
                Button("Delete Account", role: .destructive) {
                    Task {
                        do {
                            try await session.reauthenticate(
                                with: EmailPasswordCredential(
                                    email:    session.currentUser?.email ?? "",
                                    password: password
                                )
                            )
                            // Identity confirmed — proceed with deletion
                        } catch {
                            self.authError = error
                        }
                    }
                }
                .disabled(password.isEmpty || session.state.isLoading)
            }
        }
        .navigationTitle("Delete Account")
    }
}

// MARK: - Networking Layer Example
//
// ObservableSessionManager also conforms to SessionTokenProviding.
// Inject it directly (typed) or via AnyTokenProvider (erased):
//
//   // Direct — APIClient is bound to BearerToken
//   struct APIClient {
//       let tokens: any SessionTokenProviding<BearerToken>
//   }
//   let apiClient = APIClient(tokens: session)
//
//   // Erased — APIClient only needs a header string
//   struct APIClient {
//       let tokens: AnyTokenProvider
//   }
//   let apiClient = APIClient(tokens: AnyTokenProvider(session))

// MARK: - Preview Support

public final class ExampleIdentityProvider: IdentityProvider, @unchecked Sendable {
    public typealias Credential = EmailPasswordCredential
    public typealias Token      = BearerToken
    public let providerID = "example"
    public init() {}
    public func signIn(with c: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
        try await Task.sleep(nanoseconds: 600_000_000)
        guard c.email.contains("@"), c.password.count >= 6 else { throw SessionError.invalidCredentials }
        return AuthResult(
            user:  SessionUser(id: "ex-1", displayName: "Example User", email: c.email),
            token: BearerToken(accessToken: "ex-token", expiresAt: .now.addingTimeInterval(3600))
        )
    }
    public func refreshToken(_ t: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> { throw SessionError.tokenRefreshFailed }
    public func signOut(token: BearerToken) async throws {}
}

@available(iOS 17.0, macOS 14.0, *)
@MainActor
private func makePreviewSession() -> ExampleSession {
    ExampleSession(provider: ExampleIdentityProvider(), store: InMemoryCredentialStore())
}

@available(iOS 17.0, macOS 14.0, *)
#Preview("Sign In") {
    ObservableSignInView().environment(makePreviewSession())
}

@available(iOS 17.0, macOS 14.0, *)
#Preview("Home") {
    ObservableHomeView().environment(makePreviewSession())
}

#endif
