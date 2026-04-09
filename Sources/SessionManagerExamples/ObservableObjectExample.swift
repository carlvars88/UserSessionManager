// MARK: - ObservableObjectExample.swift
//
// SwiftUI example using UserSessionManager (ObservableObject).
// Compatible with iOS 16+ / macOS 12+.
//
// Wiring:
//
//   // Define a typealias once at the app level to keep view code concise.
//   typealias AppSession = UserSessionManager<MyProvider, KeychainCredentialStore<BearerToken>>
//
//   @main
//   struct MyApp: App {
//       @StateObject private var session = AppSession(
//           provider: MyProvider(),
//           store:    KeychainCredentialStore<BearerToken>()
//       )
//       var body: some Scene {
//           WindowGroup {
//               ObservableObjectRootView()
//                   .environmentObject(session)
//           }
//       }
//   }

#if canImport(SwiftUI)
import SwiftUI
import SessionManager

// Typealias keeps @EnvironmentObject annotations concise throughout this file.
// In a real app define this once at the app level with your own Provider and Store types.
typealias AppSession = UserSessionManager<PreviewProvider, InMemoryCredentialStore<BearerToken>>

// MARK: - iOS-only text field modifier helpers

private extension View {
    /// Applies email content-type hints (iOS-only modifiers).
    func emailFieldHints() -> some View {
        #if os(iOS)
        self.textContentType(.emailAddress).textInputAutocapitalization(.never)
        #else
        self
        #endif
    }
    /// Applies password content-type hint (iOS-only modifier).
    func passwordFieldHint() -> some View {
        #if os(iOS)
        self.textContentType(.password)
        #else
        self
        #endif
    }
}

// MARK: - Root View

/// Switches between SignInView and HomeView based on session state.
@available(macOS 13.0, iOS 16.0, *)
public struct ObservableObjectRootView: View {

    @EnvironmentObject var session: AppSession

    public init() {}

    public var body: some View {
        Group {
            switch session.state {
            case .loading:
                ProgressView("Restoring session…")
            case .signedOut, .failed, .expired(_):
                ObservableObjectSignInView()
            case .signedIn:
                ObservableObjectHomeView()
            }
        }
        .animation(.default, value: session.state)
    }
}

// MARK: - Sign-In View

@available(macOS 13.0, iOS 16.0, *)
public struct ObservableObjectSignInView: View {

    @EnvironmentObject var session: AppSession

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

@available(macOS 13.0, iOS 16.0, *)
public struct ObservableObjectHomeView: View {

    @EnvironmentObject var session: AppSession

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

// MARK: - Networking Layer Example
//
// The networking layer only depends on AnyTokenProvider — no knowledge of
// session state, credentials, or the concrete manager type.
//
//   struct APIClient {
//       let tokens: AnyTokenProvider
//
//       func fetchData() async throws -> Data {
//           guard let header = try await tokens.currentRawToken() else {
//               throw URLError(.userAuthenticationRequired)
//           }
//           var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
//           request.setValue("Bearer \(header)", forHTTPHeaderField: "Authorization")
//           let (data, _) = try await URLSession.shared.data(for: request)
//           return data
//       }
//   }
//
//   // Wiring (BearerToken convenience init — no rawValue closure needed):
//   let apiClient = APIClient(tokens: AnyTokenProvider(session))

// MARK: - Preview Support

final class PreviewProvider: IdentityProvider, @unchecked Sendable {
    typealias Credential = EmailPasswordCredential
    typealias Token      = BearerToken
    let providerID = "preview"
    func signIn(with c: EmailPasswordCredential) async throws -> AuthResult<BearerToken> {
        try await Task.sleep(nanoseconds: 600_000_000)
        guard c.email.contains("@"), c.password.count >= 6 else { throw SessionError.invalidCredentials }
        return AuthResult(
            user:  SessionUser(id: "preview-1", displayName: "Preview User", email: c.email),
            token: BearerToken(accessToken: "preview-token", expiresAt: .now.addingTimeInterval(3600))
        )
    }
    func refreshToken(_ t: BearerToken, currentUser: SessionUser?) async throws -> AuthResult<BearerToken> { throw SessionError.tokenRefreshFailed }
    func signOut(token: BearerToken) async throws {}
}

@available(macOS 13.0, iOS 16.0, *)
@MainActor
private func makePreviewSession() -> AppSession {
    AppSession(provider: PreviewProvider(), store: InMemoryCredentialStore())
}

@available(macOS 13.0, iOS 16.0, *)
#Preview("Sign In") {
    ObservableObjectSignInView().environmentObject(makePreviewSession())
}

@available(macOS 13.0, iOS 16.0, *)
#Preview("Home") {
    ObservableObjectHomeView().environmentObject(makePreviewSession())
}

#endif
