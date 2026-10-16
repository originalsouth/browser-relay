import Foundation

struct RelayError: LocalizedError, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

// This is a serialization boundary, not a second implementation of inspection policy.
enum Core {
    private struct Envelope<T: Decodable>: Decodable {
        let ok: Bool
        let data: T?
        let error: String?
    }

    private static func decode<T: Decodable>(_ bytes: Data) throws -> T {
        let pointer = bytes.withUnsafeBytes {
            relay_core_request($0.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        guard let pointer else { throw RelayError("The inspection core is unavailable.") }
        defer { relay_core_free(pointer) }
        let result = try JSONDecoder().decode(Envelope<T>.self, from: Data(String(cString: pointer).utf8))
        guard result.ok, let data = result.data else {
            throw RelayError(result.error ?? "The core could not finish this operation.")
        }
        return data
    }

    static func call<T: Decodable>(_ request: [String: Any]) throws -> T {
        try decode(JSONSerialization.data(withJSONObject: request))
    }

    static func work<T: Decodable & Sendable>(_ request: [String: Any]) async throws -> T {
        let data = try JSONSerialization.data(withJSONObject: request)
        return try await Task.detached(priority: .userInitiated) { try decode(data) as T }.value
    }

    static func release(_ id: UInt64) {
        let _: Empty? = try? call(["op": "route_release", "id": id])
    }
}

struct Empty: Decodable, Sendable {}
struct ValidLink: Decodable, Sendable { let url: String; let inspectionURL: String; let host: String }
struct QR: Decodable, Sendable { let width: Int; let quietZone: Int; let modules: [Bool] }
struct Certificate: Decodable, Sendable { let subject: String; let issuer: String; let detail: String }
struct RouteDecision: Decodable, Sendable {
    let id: UInt64
    let action: String
    let url: String?
    let notice: String?
    let names: [String]
    let encrypted: Bool
    let complete: Bool
    let requests: Int
}
struct LocalInsights: Decodable, Sendable {
    struct Blocklist: Decodable, Sendable {
        let summary: String?
        let detail: String
        let big: Bool?
        let nsfw: Bool?
        let stale: Bool?
    }
    struct Rank: Decodable, Sendable {
        let rank: Int?
        let position: Double?
        let color: [Double]?
        let caption: String?
        let detail: String
        let available: Bool?
        let stale: Bool?
    }
    let oisd: Blocklist
    let tranco: Rank
}
struct Geo: Decodable, Sendable {
    let name: String
    let countryCode: String
    let detail: String
    var flag: String {
        let codes = Array(countryCode.uppercased().unicodeScalars)
        guard codes.count == 2, codes.allSatisfy({ (65...90).contains($0.value) }) else { return "🌐" }
        return codes.compactMap { UnicodeScalar($0.value + 127397) }.map(String.init).joined()
    }
}
struct ListSources: Decodable, Sendable {
    struct Limits: Decodable, Sendable {
        let oisd: Int; let tranco: Int; let metadata: Int; let geo: Int; let indexMemory: Int
    }
    let big: String; let adult: String; let metadata: String; let limits: Limits
}
struct TrancoSource: Decodable, Sendable { let url: String; let date: String; let id: String }
struct CoreMessage: Decodable, Sendable { let message: String }
