import XCTest
@testable import BrowserRelay

private final class FixtureProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let url = request.url else { return }
        // Any accidental follow-up or unexpected header fails the request, without networking.
        let expectedAuth = url.host == "api.certspotter.com" && url.path == "/v1/issuances" ? "Bearer fixture-secret" : nil
        guard request.value(forHTTPHeaderField: "Cookie") == nil,
              request.value(forHTTPHeaderField: "Authorization") == expectedAuth,
              request.value(forHTTPHeaderField: "Referer") == nil else {
            client?.urlProtocol(self, didFailWithError: RelayError("Unexpected identifying header."))
            return
        }
        switch url.path {
        case "/redirect", "/v1/issuances":
            let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1",
                                           headerFields: ["Location": "https://other.invalid/private", "Set-Cookie": "token=secret"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        case "/unauthorized":
            let response = HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1",
                                           headerFields: ["WWW-Authenticate": "Basic realm=fixture"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        case "/large":
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(repeating: 65, count: 4097))
        default:
            client?.urlProtocol(self, didFailWithError: RelayError("Unexpected destination."))
            return
        }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

private final class ChallengeSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
    func cancel(_ challenge: URLAuthenticationChallenge) {}
    func performDefaultHandling(for challenge: URLAuthenticationChallenge) {}
    func rejectProtectionSpaceAndContinue(with challenge: URLAuthenticationChallenge) {}
}

final class TransferTests: XCTestCase {
    func testExplicitHistoryCredentialStaysOnItsEndpointAndRedirectIsNotFollowed() async throws {
        let result = try await Transfer(protocolClasses: [FixtureProtocol.self]).run(
            URL(string: "https://api.certspotter.com/v1/issuances?domain=github.com")!, method: "GET", bearerToken: "fixture-secret")
        XCTAssertEqual(result.status, 302)
        XCTAssertEqual(result.location, "https://other.invalid/private")
    }

    func testCredentialsAreRejectedBeforeUnrelatedDestinationsAreContacted() async throws {
        for text in ["https://github.com/", "http://api.certspotter.com/v1/issuances", "https://api.certspotter.com:8443/v1/issuances", "https://api.certspotter.com/other"] {
            do {
                _ = try await Transfer(protocolClasses: [FixtureProtocol.self]).run(URL(string: text)!, bearerToken: "fixture-secret")
                XCTFail("Credential guard should reject this endpoint")
            } catch { XCTAssertTrue(error.localizedDescription.contains("restricted")) }
        }
        do {
            _ = try await Transfer(protocolClasses: [FixtureProtocol.self]).run(URL(string: "https://api.certspotter.com/v1/issuances")!, bearerToken: "fixture-secret\ninvalid")
            XCTFail("Header injection must be rejected")
        } catch {
            XCTAssertFalse(error.localizedDescription.contains("fixture-secret"))
            XCTAssertTrue(error.localizedDescription.contains("Invalid API key"))
        }
    }

    func testAuthenticationChallengesAreDeclinedWithoutCredentialsOrCancellation() {
        let transfer = Transfer()
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        for method in [NSURLAuthenticationMethodHTTPBasic, NSURLAuthenticationMethodHTTPDigest,
                       NSURLAuthenticationMethodClientCertificate] {
            let space = URLProtectionSpace(host: "fixture.invalid", port: 443, protocol: "https",
                                           realm: "fixture", authenticationMethod: method)
            let challenge = URLAuthenticationChallenge(protectionSpace: space,
                proposedCredential: URLCredential(user: "saved", password: "secret", persistence: .none),
                previousFailureCount: 0, failureResponse: nil, error: nil, sender: ChallengeSender())
            var called = false
            transfer.urlSession(session, didReceive: challenge) { disposition, credential in
                called = true
                XCTAssertEqual(disposition, .rejectProtectionSpace)
                XCTAssertNil(credential)
            }
            XCTAssertTrue(called)
        }
    }

    func testUnauthorizedResponseRemainsAnInspectionResult() async throws {
        let result = try await Transfer(protocolClasses: [FixtureProtocol.self])
            .run(URL(string: "https://fixture.invalid/unauthorized")!)
        XCTAssertEqual(result.status, 401)
    }

    func testRedirectLocationIsReturnedForTheCore() async throws {
        let result = try await Transfer(protocolClasses: [FixtureProtocol.self])
            .run(URL(string: "https://fixture.invalid/redirect")!)
        XCTAssertEqual(result.status, 302)
        XCTAssertEqual(result.location, "https://other.invalid/private")
    }

    func testStreamingLimitRejectsOversizedResponse() async {
        do {
            _ = try await Transfer(protocolClasses: [FixtureProtocol.self])
                .run(URL(string: "https://fixture.invalid/large")!, method: "GET")
            XCTFail("An oversized response must fail.")
        } catch { XCTAssertTrue(error.localizedDescription.contains("size limit")) }
    }

    func testCancellationBeforeStartDoesNotCreateRequest() async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await Transfer(protocolClasses: [FixtureProtocol.self])
                .run(URL(string: "https://fixture.invalid/must-not-run")!)
        }
        do {
            _ = try await task.value
            XCTFail("A cancelled transfer must fail.")
        } catch {
            XCTAssertTrue(error is CancellationError || (error as NSError).code == NSURLErrorCancelled)
        }
    }
}
