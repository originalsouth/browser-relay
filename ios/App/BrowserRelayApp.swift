import SwiftUI
import WebKit

@main
struct BrowserRelayApp: App {
    var body: some Scene { WindowGroup { BrowserView() } }
}

@MainActor
final class BrowserModel: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate {
    let webView = WKWebView(frame: .zero)
    @Published var current = ""
    @Published var loading = false
    @Published var error: String?
    @Published var hasPage = false
    @Published var canGoBack = false
    @Published var canGoForward = false
    private var observations: [NSKeyValueObservation] = []
    override init() {
        super.init()
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        // Include history.pushState and fragment navigation, not only full page loads.
        observations = [
            webView.observe(\.url) { [weak self] _, _ in
                Task { @MainActor [weak self] in
                    guard let self, let url = self.webView.url else { return }
                    self.current = url.absoluteString
                }
            },
            webView.observe(\.isLoading) { [weak self] _, _ in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.loading = self.webView.isLoading
                    self.canGoBack = self.webView.canGoBack
                    self.canGoForward = self.webView.canGoForward
                }
            }
        ]
    }
    func open(_ input: String) {
        do {
            let link: ValidLink = try Core.call(["op": "validate", "url": input])
            guard let url = URL(string: link.url) else { throw RelayError("Invalid address.") }
            current = link.url
            error = nil
            hasPage = true
            webView.load(URLRequest(url: url))
        } catch { self.error = error.localizedDescription }
    }
    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) { loading = true; error = nil }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        loading = false
        current = webView.url?.absoluteString ?? current
    }
    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) { current = webView.url?.absoluteString ?? current }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { failed(error) }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { failed(error) }
    private func failed(_ failure: Error) {
        loading = false
        if (failure as NSError).code != NSURLErrorCancelled { error = failure.localizedDescription }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let scheme = navigationAction.request.url?.scheme?.lowercased()
        // Never send a page's custom scheme back to the system's default browser (ourselves).
        decisionHandler(["http", "https", "about", "blob"].contains(scheme ?? "") ? .allow : .cancel)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if navigationAction.targetFrame == nil, let url = navigationAction.request.url,
           ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
            webView.load(navigationAction.request)
        }
        return nil
    }
}

private struct WebPage: UIViewRepresentable {
    let browser: BrowserModel
    func makeUIView(context: Context) -> WKWebView { browser.webView }
    func updateUIView(_ view: WKWebView, context: Context) {}
}

struct BrowserView: View {
    @StateObject private var browser = BrowserModel()
    @State private var address = ""
    @State private var toolsLink: SelectedLink?
    @State private var showData = false
    @FocusState private var editing: Bool
    private struct SelectedLink: Identifiable { let id = UUID(); let url: String }
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    Image(systemName: "globe").foregroundStyle(.secondary)
                    TextField("Enter an https:// address", text: $address)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .focused($editing).submitLabel(.go).onSubmit { visit() }
                    Button(action: visit) { Image(systemName: "arrow.right.circle.fill") }.accessibilityLabel("Open address")
                }.padding(12).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14)).padding(12)
                if let error = browser.error { Text(error).font(.caption).foregroundStyle(.orange).padding(.horizontal) }
                if browser.hasPage {
                    WebPage(browser: browser)
                } else {
                    VStack(spacing: 20) {
                        Image(systemName: "arrow.triangle.branch").font(.system(size: 60)).foregroundStyle(.purple)
                        Text("Your link. Your call.").font(.largeTitle.bold())
                        Text("Visit an address above, or inspect it before opening. Shared links are available from the iOS Share menu.")
                            .multilineTextAlignment(.center).foregroundStyle(.secondary)
                        Button("Inspect this address") { inspectAddress() }.buttonStyle(.borderedProminent).disabled(address.isEmpty)
                    }.padding(28).frame(maxHeight: .infinity)
                }
                HStack(spacing: 24) {
                    Button { browser.webView.goBack() } label: { Image(systemName: "chevron.left") }.accessibilityLabel("Back").disabled(!browser.canGoBack)
                    Button { browser.webView.goForward() } label: { Image(systemName: "chevron.right") }.accessibilityLabel("Forward").disabled(!browser.canGoForward)
                    Button { browser.loading ? browser.webView.stopLoading() : browser.webView.reload() } label: {
                        Image(systemName: browser.loading ? "xmark" : "arrow.clockwise")
                    }.accessibilityLabel(browser.loading ? "Stop loading" : "Reload")
                    Spacer()
                    if let url = URL(string: browser.current), browser.hasPage { ShareLink(item: url).labelStyle(.iconOnly) }
                    Button { toolsLink = SelectedLink(url: browser.hasPage ? browser.current : address) } label: {
                        Image(systemName: "slider.horizontal.3")
                    }.accessibilityLabel("Link tools").disabled(browser.current.isEmpty && address.isEmpty)
                }.font(.title3).padding(16).background(.bar)
            }
            .navigationTitle("Browser Relay").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Data") { showData = true } } }
            .onChange(of: browser.current) { _, value in if !editing { address = value } }
            .onChange(of: editing) { _, value in
                if !value, browser.hasPage { address = browser.current }
            }
            .onOpenURL { url in
                // Default-browser links must render directly; inspection stays an explicit action.
                toolsLink = nil
                showData = false
                address = url.absoluteString
                browser.open(address)
            }
            .sheet(item: $toolsLink) { selected in
                NavigationStack {
                    VStack(spacing: 0) {
                        RelayView(link: selected.url)
                        HandoffView(link: selected.url)
                    }.toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { toolsLink = nil } } }
                }
            }
            .sheet(isPresented: $showData) { DataView() }
        }.preferredColorScheme(.dark).tint(Color(red: 0.66, green: 0.51, blue: 1))
    }
    private func visit() { editing = false; browser.open(address) }
    private func inspectAddress() {
        do {
            let valid: ValidLink = try Core.call(["op": "validate", "url": address])
            toolsLink = SelectedLink(url: valid.url)
        } catch { browser.error = error.localizedDescription }
    }
}

// iOS exposes selected, declared URL schemes rather than the desktop's browser registry.
private struct HandoffView: View {
    let link: String
    @State private var error: String?
    private var browsers: [(String, URL)] {
        guard let url = URL(string: link), ["http", "https"].contains(url.scheme ?? "") else { return [] }
        var candidates: [(String, URL)] = []
        var chrome = URLComponents(url: url, resolvingAgainstBaseURL: false)
        chrome?.scheme = url.scheme == "https" ? "googlechromes" : "googlechrome"
        if let target = chrome?.url { candidates.append(("Chrome", target)) }
        var firefox = URLComponents()
        firefox.scheme = "firefox"; firefox.host = "open-url"
        firefox.queryItems = [URLQueryItem(name: "url", value: link)]
        if let target = firefox.url { candidates.append(("Firefox", target)) }
        return candidates.filter { UIApplication.shared.canOpenURL($0.1) }
    }
    var body: some View {
        VStack {
            if !browsers.isEmpty {
                HStack {
                    ForEach(browsers, id: \.0) { browser in
                        Button("Open in \(browser.0)") {
                            UIApplication.shared.open(browser.1) { success in
                                if !success { error = "Could not open \(browser.0)." }
                            }
                        }.buttonStyle(.bordered)
                    }
                }
            }
            if let error { Text(error).font(.caption).foregroundStyle(.orange) }
        }.padding(.horizontal).padding(.bottom, 8)
    }
}
