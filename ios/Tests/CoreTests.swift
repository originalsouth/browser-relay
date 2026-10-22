import XCTest
@testable import BrowserRelay

private actor InsightLoads {
    var count = 0
    func load() -> LocalInsights {
        count += 1
        return LocalInsights(oisd: .init(summary: nil, detail: "fixture", big: nil, nsfw: nil, stale: nil),
                             tranco: .init(rank: nil, position: nil, color: nil, caption: nil,
                                           detail: "fixture", available: false, stale: nil))
    }
}

final class CoreTests: XCTestCase {
    func testCTDataSourcesAndHistoryPaginationStayInTheSharedCore() throws {
        let sources: CTSources = try Core.call(["op": "ct_sources"])
        XCTAssertEqual(URL(string: sources.list)?.host, "www.gstatic.com")
        XCTAssertTrue(sources.disclosure.contains("No inspected hostname"))
        let history: CertificateHistoryLookup = try Core.call(["op": "history_prepare", "host": "github.com", "after": "opaque&domain=other.example"])
        let url = URLComponents(string: history.url)!
        XCTAssertEqual(url.host, "api.certspotter.com")
        XCTAssertEqual(url.queryItems?.filter { $0.name == "domain" }.map { $0.value }, ["github.com"])
        XCTAssertTrue(history.authDisclosure.contains("account"))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data("[]".utf8).write(to: file)
        let page: CertificateHistoryPage = try Core.call(["op": "history_result", "host": "github.com", "status": 200, "path": file.path])
        XCTAssertNil(page.next)
    }

    @MainActor
    func testUnchangedHostsReuseInsightsAndRestartRefreshesThem() async throws {
        let loads = InsightLoads()
        let model = InspectionModel(transfer: { url in
            TransferResult(status: url.path == "/start" ? 302 : 200,
                           location: url.path == "/start" ? "/finish" : nil,
                           milliseconds: 1, peer: nil, certificate: nil)
        }, loadInsights: { _, _ in await loads.load() })
        for expected in 1...2 {
            model.start("https://fixture.invalid/start")
            for _ in 0..<200 {
                if !model.busy { break }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            XCTAssertEqual(model.decision?.action, "done")
            XCTAssertEqual(model.hops.count, 2)
            let count = await loads.count
            XCTAssertEqual(count, expected)
        }
    }

    @MainActor
    func testFailedRedirectStillReportsTheAttemptedPort() async throws {
        let model = InspectionModel(transfer: { url in
            if url.port == 8443 { throw RelayError("TLS fixture failed") }
            return TransferResult(status: 302, location: "https://example.org:8443/", milliseconds: 1, peer: nil, certificate: nil)
        })
        model.start("https://example.org/")
        for _ in 0..<300 {
            if !model.busy { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(model.decision?.action, "consent")
        model.continueRedirect()
        for _ in 0..<300 {
            if model.message == "TLS fixture failed", model.risk?.summary.contains("route incomplete") == true { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(model.hops.count, 1)
        XCTAssertTrue(model.risk?.factors.contains(where: { $0.id == "unusual-port" && $0.title.contains("8443") }) == true)
        XCTAssertTrue(model.risk?.summary.contains("route incomplete") == true)
    }

    @MainActor
    func testCancelledQueuedStartsDoNotConsumeRouteSlots() async throws {
        let model = InspectionModel()
        let sentinel: RouteDecision = try Core.call(["op": "route_start", "url": "https://github.com/originalsouth/browser-relay"])
        defer { Core.release(sentinel.id) }
        // These tasks cannot begin until this actor yields. Exercise both cancel
        // and restart before allocation, with more attempts than the route limit.
        for _ in 0..<64 {
            model.start("https://github.com/originalsouth/browser-relay")
            model.start("https://github.com/originalsouth/browser-relay")
            model.cancel()
        }
        for _ in 0..<256 { await Task.yield() }
        // Eviction must not mask leaked queued starts: the older active handle
        // would have been evicted if those tasks had allocated abandoned routes.
        let completed: RouteDecision = try Core.call(["op": "route_response", "id": sentinel.id, "status": 200])
        XCTAssertEqual(completed.action, "done")
        var ids: [UInt64] = []
        defer { ids.forEach { Core.release($0) } }
        for _ in 0..<32 {
            let route: RouteDecision = try Core.call(["op": "route_start", "url": "https://github.com/originalsouth/browser-relay"])
            ids.append(route.id)
        }
        XCTAssertEqual(ids.count, 32)
        XCTAssertFalse(model.busy)
    }

    @MainActor
    func testDestroyingModelReleasesConsentHandle() async throws {
        var model: InspectionModel? = InspectionModel(transfer: { _ in
            TransferResult(status: 302, location: "https://other.invalid/", milliseconds: 1,
                           peer: nil, certificate: nil)
        })
        weak var weakModel = model
        model?.start("https://fixture.invalid/")
        for _ in 0..<200 {
            if model?.busy == false { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(model?.decision?.action, "consent")
        let id = try XCTUnwrap(model?.decision?.id)
        defer { Core.release(id) }
        model = nil
        XCTAssertNil(weakModel)
        XCTAssertThrowsError(try Core.call(["op": "route_continue", "id": id]) as RouteDecision)
    }

    func testInspectionStripsFragmentWithoutChangingCopyAddress() throws {
        let link: ValidLink = try Core.call(["op": "validate", "url": "https://github.com/originalsouth/browser-relay#readme"])
        XCTAssertTrue(link.url.hasSuffix("#readme"))
        XCTAssertEqual(link.inspectionURL, "https://github.com/originalsouth/browser-relay")
        XCTAssertThrowsError(try Core.call(["op": "validate", "url": "https://user:secret@github.com/"]) as ValidLink)
    }

    func testRedirectRequiresConsentAndKeepsEarlierHTTP() throws {
        let start: RouteDecision = try Core.call(["op": "route_start", "url": "http://github.com/originalsouth/browser-relay"])
        defer { Core.release(start.id) }
        let consent: RouteDecision = try Core.call(["op": "route_response", "id": start.id, "status": 301,
                                                    "location": "https://github.com/originalsouth/browser-relay"])
        XCTAssertEqual(consent.action, "consent")
        XCTAssertFalse(consent.complete)
        XCTAssertFalse(consent.encrypted)
        let next: RouteDecision = try Core.call(["op": "route_continue", "id": start.id])
        XCTAssertEqual(next.action, "request")
        XCTAssertEqual(next.requests, 2)
        let done: RouteDecision = try Core.call(["op": "route_response", "id": start.id, "status": 200])
        XCTAssertTrue(done.complete)
        XCTAssertFalse(done.encrypted)
    }

    func testPublisherLimitsDecodeAcrossTheBridge() throws {
        let sources: ListSources = try Core.call(["op": "list_sources"])
        XCTAssertGreaterThan(sources.limits.oisd, 0)
        XCTAssertGreaterThan(sources.limits.tranco, 0)
        XCTAssertGreaterThan(sources.limits.geo, 0)
        XCTAssertGreaterThan(sources.limits.metadata, 0)
        XCTAssertGreaterThan(sources.limits.indexMemory, 0)
    }

    func testQRIsLocalAndBounded() throws {
        let code: QR = try Core.call(["op": "qr", "url": "https://github.com/originalsouth/browser-relay"])
        XCTAssertEqual(code.modules.count, code.width * code.width)
        XCTAssertGreaterThanOrEqual(code.quietZone, 4)
        XCTAssertThrowsError(try Core.call(["op": "qr", "url": String(repeating: "x", count: 107)]) as QR)
    }

    func testRiskOpRejectsTooManyHops() throws {
        let hop: [String: Any] = ["url": "https://example.org/", "status": 200]
        XCTAssertThrowsError(try Core.call(["op": "risk", "directory": NSTemporaryDirectory(), "link": "https://example.org/", "hops": Array(repeating: hop, count: 7)]) as RiskReport)
    }
    func testRiskSummaryNeverClaimsSafety() throws {
        let report: RiskReport = try Core.call(["op": "risk", "directory": NSTemporaryDirectory(), "link": "https://example.org/", "hops": [], "finished": true, "complete": true])
        XCTAssertEqual(report.summary, "No risk factors found · trust unknown")
        XCTAssertFalse(report.lookalikes)
    }
}
