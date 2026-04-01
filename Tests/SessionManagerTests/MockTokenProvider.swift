// MARK: - MockTokenProvider  (networking unit tests)
//
// Generic over Token so networking tests can use any token shape without
// any dependency on IdentityProvider, CredentialStore, or UserSessionManager.

@testable import SessionManager

final class MockTokenProvider<Token: AuthSessionToken>:
    SessionTokenProviding, @unchecked Sendable
{
    enum Behaviour {
        case success(Token)
        case failure(SessionError)
        case expiresThenSucceeds(Token)
    }

    private let behaviour: Behaviour
    private var callCount = 0

    init(_ behaviour: Behaviour) {
        self.behaviour = behaviour
    }

    func currentValidToken() async throws -> Token {
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
