import UIKit
import SwiftUI
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let items = extensionContext?.inputItems.compactMap { $0 as? NSExtensionItem } ?? []
        let providers = items.flatMap { $0.attachments ?? [] }
        guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(UTType.url.identifier) || $0.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) }) else {
            showError("Share one web address to inspect it.")
            return
        }
        let type = provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) ? UTType.url.identifier : UTType.plainText.identifier
        provider.loadItem(forTypeIdentifier: type, options: nil) { [weak self] item, error in
            let text = (item as? URL)?.absoluteString ?? (item as? String)
            DispatchQueue.main.async {
                guard let self else { return }
                do {
                    guard let text else { throw error ?? RelayError("The shared item contains no web address.") }
                    let valid: ValidLink = try Core.call(["op": "validate", "url": text.trimmingCharacters(in: .whitespacesAndNewlines)])
                    self.show(AnyView(NavigationStack {
                        RelayView(link: valid.url).toolbar {
                            ToolbarItem(placement: .confirmationAction) { Button("Done") { self.finish() } }
                        }
                    }))
                } catch { self.showError(error.localizedDescription) }
            }
        }
    }
    private func finish() { extensionContext?.completeRequest(returningItems: nil) }
    private func showError(_ message: String) {
        show(AnyView(VStack(spacing: 20) {
            Image(systemName: "link.badge.plus").font(.largeTitle)
            Text(message).multilineTextAlignment(.center)
            Button("Done") { self.finish() }
        }.padding(30).preferredColorScheme(.dark)))
    }
    private func show(_ content: AnyView) {
        let host = UIHostingController(rootView: content)
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])
        host.didMove(toParent: self)
    }
}
