// MARK: - NetworkClient.swift

import Foundation

/// A transport-agnostic closure for performing HTTP requests.
///
/// Accepts any HTTP layer — no protocol conformance, no bridge adapter, no
/// retroactive conformances. Pass one directly to any provider that requires
/// network access.
///
/// ## URLSession
///
/// ```swift
/// OAuth2Provider(configuration: config, networkHandler: URLSession.shared.data(for:))
/// ```
///
/// ## URLSession with SSL pinning
///
/// ```swift
/// let pinned = URLSession(configuration: .default, delegate: PinningDelegate(), delegateQueue: nil)
/// OAuth2Provider(configuration: config, networkHandler: pinned.data(for:))
/// ```
///
/// ## Alamofire
///
/// ```swift
/// OAuth2Provider(configuration: config) { request in
///     let task = AF.request(request)
///     let data = try await task.serializingData().value
///     let response = task.response!
///     return (data, response)
/// }
/// ```
///
/// ## Test stub
///
/// ```swift
/// OAuth2Provider(configuration: config) { _ in (mockData, mockResponse) }
/// ```
public typealias SMNetworkHandler = @Sendable (URLRequest) async throws -> (Data, URLResponse)
