import SwiftUI

struct Hop: Identifiable {
    let id = UUID()
    let url: String
    let result: TransferResult
    let certificate: Certificate?
    let geo: Geo?
}

@MainActor
final class InspectionModel: ObservableObject {
    @Published var hops: [Hop] = []
    @Published var decision: RouteDecision?
    @Published var insights: LocalInsights?
    @Published var risk: RiskReport?
    @Published var message: String?
    @Published var busy = false
    private var task: Task<Void, Never>?
    private var routeID: UInt64?
    private var generation = UUID()
    private var insightNames: [String]?
    private var link = ""
    private var attempts: [[String: Any]] = []
    private let transfer: @Sendable (URL) async throws -> TransferResult
    private let loadInsights: @Sendable (URL, [String]) async throws -> LocalInsights

    init(transfer: @escaping @Sendable (URL) async throws -> TransferResult = { try await Transfer().run($0) },
         loadInsights: @escaping @Sendable (URL, [String]) async throws -> LocalInsights = { root, names in
             try await Core.work(["op": "insights", "directory": root.path, "names": names])
         }) {
        self.transfer = transfer
        self.loadInsights = loadInsights
    }

    deinit {
        task?.cancel()
        if let routeID { Core.release(routeID) }
    }

    func start(_ link: String) {
        cancel()
        self.link = link
        attempts = []
        hops = []; decision = nil; insights = nil; risk = nil; insightNames = nil; message = nil
        let token = generation
        busy = true
        task = Task {
            do {
                try Task.checkCancellation()
                guard token == generation else { return }
                // No suspension between the guard, allocation and ownership assignment.
                let first: RouteDecision = try Core.call(["op": "route_start", "url": link])
                routeID = first.id
                try await drive(first, token: token)
            } catch { await failed(error, token: token) }
        }
    }

    func continueRedirect() {
        guard let routeID, decision?.action == "consent", !busy else { return }
        let token = generation
        busy = true
        task = Task {
            do {
                try Task.checkCancellation()
                guard token == generation else { return }
                let next: RouteDecision = try Core.call(["op": "route_continue", "id": routeID])
                try await drive(next, token: token)
            } catch { await failed(error, token: token) }
        }
    }

    private func drive(_ initial: RouteDecision, token: UUID) async throws {
        var next = initial
        while true {
            try Task.checkCancellation()
            guard token == generation else { throw CancellationError() }
            decision = next
            let root = try Storage.directory()
            if insightNames != next.names {
                let local = try await loadInsights(root, next.names)
                try Task.checkCancellation()
                guard token == generation else { throw CancellationError() }
                insights = local
                insightNames = next.names
            }
            guard next.action == "request", let text = next.url, let url = URL(string: text) else { break }
            attempts.append(["url": text])
            await refreshRisk(root: root, finished: false, complete: false, token: token)
            try Task.checkCancellation()
            guard token == generation else { throw CancellationError() }
            let result = try await transfer(url)
            try Task.checkCancellation()
            guard token == generation else { throw CancellationError() }
            var certificate: Certificate?
            if let bytes = result.certificate {
                certificate = try? Core.call(["op": "certificate", "der": Array(bytes)])
            }
            var geo: Geo?
            if let ip = result.peer {
                geo = try? await Core.work(["op": "geo", "ip": ip, "path": root.appendingPathComponent("GeoIP.mmdb").path])
            }
            try Task.checkCancellation()
            guard token == generation else { throw CancellationError() }
            attempts[attempts.count - 1]["status"] = result.status
            if let c = certificate, let a = c.notBefore, let b = c.notAfter {
                attempts[attempts.count - 1]["notBefore"] = a
                attempts[attempts.count - 1]["notAfter"] = b
            }
            hops.append(Hop(url: text, result: result, certificate: certificate, geo: geo))
            await refreshRisk(root: root, finished: false, complete: false, token: token)
            try Task.checkCancellation()
            guard token == generation else { throw CancellationError() }
            var response: [String: Any] = ["op": "route_response", "id": next.id, "status": result.status]
            if let location = result.location { response["location"] = location }
            next = try Core.call(response)
        }
        let finalRoot = try Storage.directory()
        await refreshRisk(root: finalRoot, finished: true, complete: next.complete, token: token)
        try Task.checkCancellation()
        guard token == generation else { throw CancellationError() }
        busy = false
        message = next.notice
        if next.action != "consent" { releaseRoute() }
    }

    private func refreshRisk(root: URL, finished: Bool, complete: Bool, token: UUID) async {
        let report: RiskReport? = try? await Core.work(["op": "risk", "directory": root.path, "link": link, "hops": attempts,
                                                        "finished": finished, "complete": complete])
        guard !Task.isCancelled, token == generation else { return }
        // A failed recompute keeps the last report rather than blanking the panel.
        if let report { risk = report }
    }

    private func failed(_ error: Error, token: UUID) async {
        guard token == generation else { return }
        busy = false
        if !(error is CancellationError) { message = error.localizedDescription }
        releaseRoute()
        // A user stop bumps the generation first, so only real failures reach here with a current token.
        guard !(error is CancellationError), let root = try? Storage.directory() else { return }
        await refreshRisk(root: root, finished: true, complete: false, token: token)
    }

    private func releaseRoute() {
        if let routeID { Core.release(routeID) }
        routeID = nil
    }

    func cancel() {
        generation = UUID()
        task?.cancel()
        task = nil
        releaseRoute()
        busy = false
    }
}
