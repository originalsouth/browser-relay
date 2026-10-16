import Foundation

// Container discovery belongs to iOS; formats, parsing and atomic cache replacement belong to Rust.
enum Storage {
    static func directory() throws -> URL {
        let manager = FileManager.default
        let base: URL
        if let group = Bundle.main.object(forInfoDictionaryKey: "RelayAppGroup") as? String,
           let container = manager.containerURL(forSecurityApplicationGroupIdentifier: group) {
            base = container
        } else {
            base = try manager.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                   appropriateFor: nil, create: true)
        }
        let root = base.appendingPathComponent("BrowserRelay", isDirectory: true)
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        var excluded = root
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try excluded.setResourceValues(values)
        return root
    }

    static func importGeo(_ source: URL) throws {
        let access = source.startAccessingSecurityScopedResource()
        defer { if access { source.stopAccessingSecurityScopedResource() } }
        let sources: ListSources = try Core.call(["op": "list_sources"])
        let attributes = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard attributes.isRegularFile == true, let size = attributes.fileSize, size <= sources.limits.geo else {
            throw RelayError("Choose a country MMDB database under \(sources.limits.geo / 1024 / 1024) MiB.")
        }
        let destination = try directory().appendingPathComponent("GeoIP.mmdb")
        let _: CoreMessage = try Core.call(["op": "validate_geo", "path": source.path])
        try Data(contentsOf: source).write(to: destination, options: .atomic)
    }

    static func updateLists(status: @escaping @MainActor @Sendable (String) -> Void) async throws {
        let sources: ListSources = try Core.call(["op": "list_sources"])
        let root = try directory()
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        func download(_ text: String, _ name: String, _ cap: Int) async throws -> URL {
            guard let url = URL(string: text), url.scheme == "https" else { throw RelayError("Invalid publisher URL.") }
            let file = temporary.appendingPathComponent(name)
            let response = try await Transfer().run(url, method: "GET", limit: cap, to: file)
            guard response.status == 200 else { throw RelayError("Publisher returned HTTP \(response.status); no redirects followed.") }
            return file
        }
        await status("Downloading OISD…")
        let big = try await download(sources.big, "big.txt", sources.limits.oisd)
        let adult = try await download(sources.adult, "adult.txt", sources.limits.oisd)
        try Task.checkCancellation()
        let _: CoreMessage = try await Core.work(["op": "update_oisd", "big": big.path, "adult": adult.path, "directory": root.path])
        await status("OISD updated. Downloading Tranco…")
        let metadata = try await download(sources.metadata, "metadata.json", sources.limits.metadata)
        let source: TrancoSource = try await Core.work(["op": "tranco_metadata", "path": metadata.path])
        let ranks = try await download(source.url, "tranco.csv", sources.limits.tranco)
        try Task.checkCancellation()
        let _: CoreMessage = try await Core.work(["op": "update_tranco", "listID": source.id, "sourceDate": source.date,
                                                 "path": ranks.path, "directory": root.path])
        await status("OISD and Tranco are ready. Lookups stay on this device.")
    }
}
