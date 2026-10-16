import Foundation
import Security

struct TransferResult: Sendable {
    let status: Int
    let location: String?
    let milliseconds: Double
    let peer: String?
    let certificate: Data?
}

// OS boundary: a bounded, ephemeral request. Redirects are returned to Rust, never followed here.
// All response state lives on the serial delegate queue. The lock only protects start/cancel.
final class Transfer: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let protocolClasses: [AnyClass]?
    init(protocolClasses: [AnyClass]? = nil) {
        self.protocolClasses = protocolClasses
        super.init()
    }
    private var session: URLSession?
    private var cancelled = false
    private var continuation: CheckedContinuation<TransferResult, Error>?
    private var response: HTTPURLResponse?
    private var certificate: Data?
    private var peer: String?
    private var received = 0
    private var limit = 0
    private var output: FileHandle?
    private var started = ProcessInfo.processInfo.systemUptime

    func run(_ url: URL, method: String = "HEAD", limit: Int = 4096, to file: URL? = nil) async throws -> TransferResult {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                start(url, method: method, limit: limit, file: file, continuation: continuation)
            }
        } onCancel: { self.cancel() }
    }

    private func start(_ url: URL, method: String, limit: Int, file: URL?, continuation: CheckedContinuation<TransferResult, Error>) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled else { continuation.resume(throwing: CancellationError()); return }
        do {
            if let file {
                guard FileManager.default.createFile(atPath: file.path, contents: nil) else {
                    throw RelayError("Cannot create the temporary download.")
                }
                output = try FileHandle(forWritingTo: file)
            }
        } catch { continuation.resume(throwing: error); return }
        self.continuation = continuation
        self.limit = limit
        started = ProcessInfo.processInfo.systemUptime
        let configuration = URLSessionConfiguration.ephemeral
        if let protocolClasses { configuration.protocolClasses = protocolClasses }
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = method == "HEAD" ? 20 : 180
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        self.session = session
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("BrowserRelay/0.2", forHTTPHeaderField: "User-Agent")
        session.dataTask(with: request).resume()
    }

    private func cancel() {
        lock.lock()
        cancelled = true
        let current = session
        lock.unlock()
        current?.invalidateAndCancel()
    }

    private func finish(_ result: Result<TransferResult, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        try? output?.close()
        output = nil
        lock.lock()
        let current = session
        session = nil
        lock.unlock()
        current?.invalidateAndCancel()
        continuation.resume(with: result)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        handle(challenge, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        handle(challenge, completionHandler: completionHandler)
    }

    private func handle(_ challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            // Inspect anonymously. Decline this authentication method rather than
            // cancelling the request or using a saved/proposed credential.
            completionHandler(.rejectProtectionSpace, nil)
            return
        }
        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        // Preserve the OS-created SSL/hostname policy, adding cached-only revocation.
        var policies: CFArray?
        guard SecTrustCopyPolicies(trust, &policies) == errSecSuccess,
              let existing = policies as? [SecPolicy],
              let revocation = SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod | kSecRevocationNetworkAccessDisabled),
              SecTrustSetPolicies(trust, (existing + [revocation]) as CFArray) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            finish(.failure(RelayError("TLS verification failed. Certificate checks were not bypassed.")))
            return
        }
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
            certificate = SecCertificateCopyData(leaf) as Data
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            finish(.failure(RelayError("The server did not return an HTTP response.")))
            return
        }
        // A HEAD Content-Length describes the resource, not a downloaded body.
        if dataTask.originalRequest?.httpMethod != "HEAD", response.expectedContentLength > Int64(limit) {
            completionHandler(.cancel)
            finish(.failure(RelayError("The download exceeds its size limit.")))
            return
        }
        self.response = http
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        received += data.count
        guard received <= limit else {
            finish(.failure(RelayError("The response exceeds its size limit.")))
            return
        }
        do { try output?.write(contentsOf: data) }
        catch { finish(.failure(error)) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        peer = metrics.transactionMetrics.last?.remoteAddress
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)); return }
        guard let response else { finish(.failure(RelayError("No response received."))); return }
        finish(.success(TransferResult(status: response.statusCode,
            location: response.value(forHTTPHeaderField: "Location"),
            milliseconds: max(0, ProcessInfo.processInfo.systemUptime - started) * 1000,
            peer: peer, certificate: certificate)))
    }
}
