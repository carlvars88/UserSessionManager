// MARK: - NetworkClient.swift
//
// A transport-agnostic HTTP contract for identity providers.
// Lives in the SessionManager module so any IdentityProvider implementation
// — in the IdentityProviders target or in a consumer's own app — can use
// it without extra imports.
//
// Design:
//   • One protocol requirement:  data(for:) — pure transport, usable as `any SMNetworkClient`
//   • Two default extensions:    send(...)   — transport + status check (discardable Data)
//                                decode(...) — transport + status check + JSON decode

import Foundation

// MARK: - SMNetworkClient

/// A transport-agnostic HTTP contract for identity provider network calls.
///
/// Implement `data(for:)` — the single protocol requirement — to inject SSL
/// pinning, certificate validation, request interceptors, response logging,
/// or a test double. The `send` and `decode` conveniences are provided by
/// default extensions and work on any conformer automatically.
///
/// The library ships no concrete implementations. Add the conformance once
/// in your app target and inject the instance into any provider that accepts
/// an `SMNetworkClient`:
///
/// ## URLSession (most common)
///
/// ```swift
/// // In your app target — add once
/// extension URLSession: SMNetworkClient {}
///
/// // SSL pinning via a custom delegate
/// class PinningDelegate: NSObject, URLSessionDelegate {
///     func urlSession(
///         _ session: URLSession,
///         didReceive challenge: URLAuthenticationChallenge,
///         completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
///     ) {
///         guard
///             let trust = challenge.protectionSpace.serverTrust,
///             verifyPinnedCertificate(trust)
///         else { completionHandler(.cancelAuthenticationChallenge, nil); return }
///         completionHandler(.useCredential, URLCredential(trust: trust))
///     }
/// }
///
/// let pinned = URLSession(configuration: .default, delegate: PinningDelegate(), delegateQueue: nil)
/// let provider = OAuth2Provider(configuration: config, networkClient: pinned)
/// ```
///
/// ## Interceptor / logging wrapper
///
/// ```swift
/// struct LoggingClient: SMNetworkClient {
///     let inner: any SMNetworkClient
///
///     func data(for request: URLRequest) async throws -> (Data, URLResponse) {
///         print("→ \(request.httpMethod ?? "GET") \(request.url!)")
///         let result = try await inner.data(for: request)
///         print("← \((result.1 as? HTTPURLResponse)?.statusCode ?? 0)")
///         return result
///     }
/// }
/// ```
///
/// ## Test stub
///
/// ```swift
/// struct StubClient: SMNetworkClient {
///     let data: Data
///     let statusCode: Int
///
///     func data(for request: URLRequest) async throws -> (Data, URLResponse) {
///         (data, HTTPURLResponse(url: request.url!, statusCode: statusCode,
///                               httpVersion: nil, headerFields: nil)!)
///     }
/// }
/// ```
public protocol SMNetworkClient: Sendable {
    /// Perform the request and return the raw response body and metadata.
    ///
    /// HTTP-level errors (4xx, 5xx) are returned as a non-throwing
    /// `(Data, URLResponse)`. Status checking is handled by the `send` and
    /// `decode` extensions so each caller gets consistent error mapping.
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

// MARK: - Default extensions

public extension SMNetworkClient {

    /// Send a request, check the HTTP status, and return the raw body.
    ///
    /// - Returns: The response body on 2xx.
    /// - Throws: `SessionError.invalidCredentials` on 401 / 403.
    /// - Throws: `SessionError.providerError` on any other non-2xx status or
    ///   a non-HTTP response.
    @discardableResult
    func send(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await self.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw SessionError.providerError("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 || http.statusCode == 403 {
                throw SessionError.invalidCredentials
            }
            let body = String(data: data, encoding: .utf8) ?? "No body"
            throw SessionError.providerError("HTTP \(http.statusCode): \(body)")
        }
        return data
    }

    /// Send a request, check the HTTP status, and JSON-decode the body as `T`.
    ///
    /// - Returns: A decoded `T` on 2xx with a valid JSON body.
    /// - Throws: `SessionError.invalidCredentials` on 401 / 403.
    /// - Throws: `SessionError.providerError` on any other non-2xx status,
    ///   a non-HTTP response, or a JSON decode failure.
    func decode<T: Decodable>(_ type: T.Type, from request: URLRequest) async throws -> T {
        let data = try await send(request)
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw SessionError.providerError("Response decode failed: \(error.localizedDescription)")
        }
    }
}

