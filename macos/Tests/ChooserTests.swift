import AppKit
import XCTest
@testable import BrowserRelay

@MainActor
private final class PendingLaunch {
    var urls: [URL] = []
    var continuation: CheckedContinuation<Void, Error>?
    func run(_ urls: [URL], _: Browser) async throws {
        self.urls = urls
        try await withCheckedThrowingContinuation { continuation = $0 }
    }
}

final class ChooserTests: XCTestCase {
    private let link = URL(string: "https://github.com/originalsouth/browser-relay?q=a%2Fb#readme")!
    private let browser = Browser(id: "org.fixture.browser", name: "Fixture", application: URL(fileURLWithPath: "/Applications/Fixture.app"))

    @MainActor
    func testLaunchMustFinishBeforeCancelOrCloseCanClearTheLink() async throws {
        let pending = PendingLaunch()
        let model = RelayModel(launch: pending.run)
        var closed = false
        model.closeWindow = { closed = true }
        model.receive([link])
        model.open(in: browser)
        XCTAssertTrue(model.busy)
        model.finish()
        model.clear()
        XCTAssertNotNil(model.request)
        for _ in 0..<200 {
            if pending.continuation != nil { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(pending.urls, [link])
        XCTAssertFalse(closed)
        let continuation = try XCTUnwrap(pending.continuation)
        continuation.resume()
        for _ in 0..<100 where model.busy { await Task.yield() }
        XCTAssertFalse(model.busy)
        XCTAssertTrue(closed)
        XCTAssertNil(model.request)
    }

    @MainActor
    func testFailedLaunchRetainsTheOriginalAddressAndAllowsRetry() async {
        let model = RelayModel(launch: { _, _ in throw RelayError("Fixture launch failure") })
        model.receive([link])
        model.open(in: browser)
        for _ in 0..<100 where model.busy { await Task.yield() }
        XCTAssertFalse(model.busy)
        XCTAssertEqual(model.request?.text, link.absoluteString)
        XCTAssertTrue(model.message?.contains("Fixture launch failure") == true)
    }

    @MainActor
    func testIncomingLinksQueueWithoutReplacingTheCurrentChoice() {
        let model = RelayModel(launch: { _, _ in XCTFail("Receiving links must never launch") })
        let next = URL(string: "https://github.com/originalsouth/browser-relay/issues")!
        model.receive([link])
        let id = model.request?.id
        model.receive([next])
        XCTAssertEqual(model.request?.id, id)
        XCTAssertEqual(model.pending.count, 1)
        model.finish()
        XCTAssertEqual(model.request?.urls, [next])
        XCTAssertTrue(model.pending.isEmpty)
        XCTAssertTrue(model.browsers.isEmpty) // Utilities do not depend on discovery.
    }

    @MainActor
    func testInvalidBatchIsRejectedBeforeAnyChoiceIsQueued() {
        let model = RelayModel()
        model.receive([link, URL(fileURLWithPath: "/tmp/private.txt")])
        XCTAssertNil(model.request)
        XCTAssertNotNil(model.message)
        model.receive([URL(string: "https://user:secret@github.com/")!])
        XCTAssertNil(model.request)
    }

    func testDiscoveryExcludesEveryRelayCopyAndDeduplicatesBundleIDs() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        func bundle(_ name: String, _ id: String) throws -> URL {
            let url = root.appendingPathComponent(name + ".app")
            let contents = url.appendingPathComponent("Contents")
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            let data = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": id,
                "CFBundleName": name, "CFBundlePackageType": "APPL"], format: .xml, options: 0)
            try data.write(to: contents.appendingPathComponent("Info.plist"))
            return url
        }
        let first = try bundle("Browser", "org.fixture.browser")
        let duplicate = try bundle("Browser Copy", "org.fixture.browser")
        let relay = try bundle("Relay Copy", BrowserRegistry.relayID)
        let browsers = BrowserRegistry.candidates([first, duplicate, relay])
        XCTAssertEqual(browsers.map(\.id), ["org.fixture.browser"])
    }
}
