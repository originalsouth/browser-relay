import AppKit

struct Browser: Identifiable, Sendable {
    let id: String
    let name: String
    let application: URL
}

// This boundary consults Launch Services only. It never opens the discovery URL.
enum BrowserRegistry {
    static let relayID = "io.github.originalsouth.browser-relay"

    static func candidates(_ urls: [URL], ownURL: URL = Bundle.main.bundleURL) -> [Browser] {
        var identifiers = Set<String>()
        let own = ownURL.resolvingSymlinksInPath().standardizedFileURL
        return urls.compactMap { url in
            let resolved = url.resolvingSymlinksInPath().standardizedFileURL
            guard resolved != own, let bundle = Bundle(url: resolved),
                  let id = bundle.bundleIdentifier, id != relayID,
                  identifiers.insert(id.lowercased()).inserted else { return nil }
            let name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String
                ?? resolved.deletingPathExtension().lastPathComponent
            return Browser(id: id, name: name, application: resolved)
        }
    }

    static func discover() -> [Browser] {
        let workspace = NSWorkspace.shared
        let https = URL(string: "https://github.com/originalsouth/browser-relay")!
        let http = URL(string: "http://github.com/originalsouth/browser-relay")!
        let urls = workspace.urlsForApplications(toOpen: https)
        let httpIDs = Set(workspace.urlsForApplications(toOpen: http).compactMap { Bundle(url: $0)?.bundleIdentifier })
        let preferred = workspace.urlForApplication(toOpen: https).flatMap { Bundle(url: $0)?.bundleIdentifier }
        return candidates(urls).filter { httpIDs.contains($0.id) }.sorted {
            if ($0.id == preferred) != ($1.id == preferred) { return $0.id == preferred }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    @MainActor
    static func open(_ urls: [URL], in browser: Browser) async throws {
        guard browser.id != relayID,
              browser.application.resolvingSymlinksInPath() != Bundle.main.bundleURL.resolvingSymlinksInPath() else {
            throw RelayError("Browser Relay cannot forward a link to itself.")
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        _ = try await NSWorkspace.shared.open(urls, withApplicationAt: browser.application, configuration: configuration)
    }

    @MainActor
    static func makeDefault() async throws {
        // macOS presents its own consent dialog. Report partial failures rather than hiding them.
        for scheme in ["http", "https"] {
            do {
                try await NSWorkspace.shared.setDefaultApplication(at: Bundle.main.bundleURL, toOpenURLsWithScheme: scheme)
            } catch {
                throw RelayError("Could not set the \(scheme.uppercased()) default: \(error.localizedDescription). Check Default web browser in System Settings.")
            }
        }
    }
}
