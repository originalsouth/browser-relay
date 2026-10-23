import SwiftUI
import AppKit

private let accent = Color(red: 0.66, green: 0.51, blue: 1)
private let background = Color(red: 0.055, green: 0.045, blue: 0.095)

private enum Tool: String, Identifiable {
    case qr, inspect
    var id: String { rawValue }
}

struct ChooserView: View {
    @ObservedObject var model: RelayModel
    @State private var tool: Tool?
    @State private var confirmDefault = false
    @FocusState private var editing: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            if let request = model.request {
                choices(request)
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Every link deserves a choice.").font(.title2.weight(.semibold))
                    Text("Paste a web address, or make Browser Relay your default browser to choose where links open.")
                        .foregroundStyle(.secondary)
                    TextField("https://github.com/originalsouth/browser-relay", text: $model.address)
                        .textFieldStyle(.roundedBorder).focused($editing).onSubmit { model.submit() }
                    Button("Choose where it goes") { editing = false; model.submit() }
                        .buttonStyle(.borderedProminent).disabled(model.address.isEmpty || model.busy)
                }.padding(.vertical, 18)
                Spacer(minLength: 0)
            }
            if let message = model.message {
                Text(message).font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            footer
        }
        .padding(24).frame(minWidth: 392, minHeight: 380)
        .background(background).preferredColorScheme(.dark).tint(accent)
        .sheet(item: $tool) { selected in
            if let request = model.request, let url = request.urls.first {
                if selected == .qr {
                    QRView(link: url.absoluteString).frame(width: 430, height: 510)
                } else {
                    NavigationStack {
                        RelayView(link: url.absoluteString, startImmediately: true)
                            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { tool = nil } } }
                    }.frame(minWidth: 640, idealWidth: 720, minHeight: 540, idealHeight: 680)
                }
            }
        }
        .sheet(isPresented: $model.showData) { DataView().frame(width: 580, height: 580) }
        .confirmationDialog("Use Browser Relay as your default browser?", isPresented: $confirmDefault, titleVisibility: .visible) {
            Button("Set HTTP and HTTPS default") { model.makeDefault() }
        } message: {
            Text("Web links from other apps will open this chooser. macOS may ask you to confirm. You can change this in System Settings → Desktop & Dock → Default web browser.")
        }
        .onChange(of: model.request?.id) { _, _ in tool = nil }
        .onExitCommand {
            if !model.busy && tool == nil && !model.showData { model.finish() }
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(nsImage: NSImage(named: NSImage.applicationIconName) ?? NSImage())
                .resizable().frame(width: 56, height: 56)
            VStack(alignment: .leading, spacing: 4) {
                Text("Browser Relay").font(.title.weight(.bold))
                Text("YOUR LINK. YOUR CALL.").font(.caption.weight(.bold)).tracking(2).foregroundStyle(accent)
            }
            Spacer()
            if model.busy { ProgressView().controlSize(.small) }
        }
    }

    private func choices(_ request: LinkRequest) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(request.text).font(.callout.monospaced()).lineLimit(3).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(14)
                .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
            if request.urls.count > 1 {
                Text("\(request.urls.count) links · open together or copy as separate lines")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ScrollView {
                VStack(spacing: 8) {
                    ForEach(Array(model.browsers.enumerated()), id: \.element.id) { index, browser in
                        Button { model.open(in: browser) } label: {
                            HStack(spacing: 14) {
                                Image(nsImage: NSWorkspace.shared.icon(forFile: browser.application.path))
                                    .resizable().frame(width: 34, height: 34)
                                Text(browser.name).font(.headline)
                                Spacer()
                                if index < 9 { Text("⌘\(index + 1)").font(.caption.monospaced()).foregroundStyle(.secondary) }
                                Image(systemName: "arrow.up.right").foregroundStyle(accent)
                            }.padding(14).contentShape(Rectangle())
                        }
                        .buttonStyle(ChoiceStyle())
                        .shortcut(index)
                    }
                    if model.discovering { ProgressView("Finding browsers…").padding(10) }
                    else if model.browsers.isEmpty {
                        Text("No registered web browsers found. Copy, QR and inspection are still available.")
                            .font(.caption).foregroundStyle(.secondary).padding(10)
                    }
                    utility("Copy link", symbol: "doc.on.doc", hint: "⇧⌘C", action: model.copy)
                        .keyboardShortcut("c", modifiers: [.command, .shift])
                    utility("Show QR code", symbol: "qrcode", hint: "⌘R") { tool = .qr }
                        .keyboardShortcut("r").disabled(request.urls.count != 1)
                    utility("Inspect link", symbol: "checkmark.shield", hint: "⌘I") { tool = .inspect }
                        .keyboardShortcut("i").disabled(request.urls.count != 1)
                }.padding(2)
            }.scrollBounceBehavior(.basedOnSize)
            .disabled(model.busy)
            Text("Inspect contacts this address, including its path and query. QR and copy stay on this Mac.")
                .font(.caption).foregroundStyle(.secondary)
            if !model.pending.isEmpty { Text("\(model.pending.count) more choices waiting").font(.caption).foregroundStyle(accent) }
        }
    }

    private func utility(_ title: String, symbol: String, hint: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: symbol).font(.title3).frame(width: 34).foregroundStyle(accent)
                Text(title).font(.headline)
                Spacer()
                Text(hint).font(.caption.monospaced()).foregroundStyle(.secondary)
            }.padding(14).contentShape(Rectangle())
        }.buttonStyle(ChoiceStyle())
    }

    private var footer: some View {
        HStack {
            Button("Local data") { model.showData = true }
            Menu {
                Button("Refresh browsers") { model.refreshBrowsers() }.disabled(model.discovering)
                Button("Make default browser…") { confirmDefault = true }
            } label: { Image(systemName: "gearshape") }.menuStyle(.borderlessButton).frame(width: 24)
            Spacer()
            Button(model.pending.isEmpty ? "Close" : "Skip link") { model.finish() }
        }.buttonStyle(.borderless).font(.callout).disabled(model.busy)
    }
}

private struct ChoiceStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        ChoiceSurface(configuration: configuration)
    }
    private struct ChoiceSurface: View {
        let configuration: ButtonStyle.Configuration
        @Environment(\.isEnabled) private var enabled
        @State private var hovered = false
        var body: some View {
            configuration.label
                .foregroundStyle(.white.opacity(enabled ? 1 : 0.4))
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(accent.opacity(configuration.isPressed ? 0.22 : (hovered && enabled ? 0.14 : 0.055)), in: RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(accent.opacity(hovered && enabled ? 0.45 : 0.12)))
                .scaleEffect(configuration.isPressed ? 0.99 : 1)
                .animation(.easeOut(duration: 0.12), value: hovered)
                .onHover { hovered = $0 }
        }
    }
}

private extension View {
    @ViewBuilder func shortcut(_ index: Int) -> some View {
        if index < 9 { self.keyboardShortcut(KeyEquivalent(Character(String(index + 1)))) }
        else { self }
    }
}
