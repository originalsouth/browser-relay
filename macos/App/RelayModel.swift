import AppKit
import SwiftUI

struct LinkRequest: Identifiable {
    let id = UUID()
    let urls: [URL]
    var text: String { urls.map(\.absoluteString).joined(separator: "\n") }
}

@MainActor
final class RelayModel: ObservableObject {
    @Published private(set) var request: LinkRequest?
    @Published private(set) var pending: [LinkRequest] = []
    @Published private(set) var browsers: [Browser] = []
    @Published private(set) var discovering = false
    @Published private(set) var busy = false
    @Published var address = ""
    @Published var message: String?
    @Published var showData = false
    var closeWindow: () -> Void = {}
    private let launch: @MainActor ([URL], Browser) async throws -> Void
    private var discovery: Task<Void, Never>?

    init(launch: @escaping @MainActor ([URL], Browser) async throws -> Void = BrowserRegistry.open) {
        self.launch = launch
    }

    func refreshBrowsers() {
        guard !discovering else { return }
        discovering = true
        discovery = Task {
            let found = await Task.detached(priority: .userInitiated) { BrowserRegistry.discover() }.value
            browsers = found
            discovering = false
        }
    }

    func submit() {
        do {
            let valid: ValidLink = try Core.call(["op": "validate", "url": address.trimmingCharacters(in: .whitespacesAndNewlines)])
            guard let url = URL(string: valid.url) else { throw RelayError("Invalid web address.") }
            receive([url])
        } catch { message = error.localizedDescription }
    }

    func receive(_ urls: [URL]) {
        // Preserve the exact encoded URL for copying/opening; validate separately.
        // Bound external events and keep an existing choice/inspection intact.
        guard !urls.isEmpty else { return }
        guard urls.count <= 32, pending.count < 32 else {
            message = "Too many waiting links. Finish or cancel a choice first."
            return
        }
        do {
            for url in urls {
                let _: ValidLink = try Core.call(["op": "validate", "url": url.absoluteString])
            }
            let next = LinkRequest(urls: urls)
            if request == nil { request = next; message = nil }
            else { pending.append(next) }
        } catch { message = error.localizedDescription }
    }

    func open(in browser: Browser) {
        guard !busy, let request else { return }
        busy = true
        message = nil
        Task {
            do {
                try await launch(request.urls, browser)
                busy = false
                finish()
            } catch {
                busy = false
                message = "Could not open \(browser.name): \(error.localizedDescription)"
            }
        }
    }

    func copy() {
        guard !busy, let request else { return }
        NSPasteboard.general.clearContents()
        guard NSPasteboard.general.setString(request.text, forType: .string) else {
            message = "The clipboard is unavailable. Please try again."
            return
        }
        finish()
    }

    func finish() {
        guard !busy else { return }
        message = nil
        address = ""
        if !pending.isEmpty { request = pending.removeFirst() }
        else { request = nil; closeWindow() }
    }

    func clear() {
        guard !busy else { return }
        request = nil; pending = []; address = ""; message = nil; showData = false
    }

    func makeDefault() {
        guard !busy else { return }
        busy = true
        Task {
            do {
                try await BrowserRegistry.makeDefault()
                message = "Browser Relay is now the default for HTTP and HTTPS links."
            } catch { message = error.localizedDescription }
            busy = false
        }
    }
}
