import SwiftUI
import UIKit

private let violet = Color(red: 0.66, green: 0.51, blue: 1)
private let panel = Color(red: 0.10, green: 0.09, blue: 0.16)

struct RelayView: View {
    let link: String
    @StateObject private var inspection = InspectionModel()
    @State private var showQR = false
    @State private var copied = false
    @State private var inspected = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Label("YOUR LINK. YOUR CALL.", systemImage: "arrow.triangle.branch")
                    .font(.caption.weight(.bold)).tracking(2).foregroundStyle(violet)
                Text(link).font(.callout.monospaced()).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(16)
                    .background(panel, in: RoundedRectangle(cornerRadius: 18))
                HStack(spacing: 12) {
                    Button {
                        UIPasteboard.general.string = link
                        copied = true
                    } label: { Label(copied ? "Copied" : "Copy link", systemImage: copied ? "checkmark" : "doc.on.doc") }
                    Button { showQR = true } label: { Label("Show QR", systemImage: "qrcode") }
                }.buttonStyle(.bordered).tint(violet)
                if !inspected {
                    Button {
                        inspected = true
                        inspection.start(link)
                    } label: {
                        Label("Inspect link", systemImage: "checkmark.shield")
                            .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 8)
                    }.buttonStyle(.borderedProminent).tint(violet).foregroundStyle(.black)
                    Text("Contacts this address, including its path and query. No page scripts, browser cookies or automatic cross-site redirects. Local lists stay on this device.")
                        .font(.footnote).foregroundStyle(.secondary)
                } else {
                    dashboard
                }
            }.padding(20)
        }
        .scrollBounceBehavior(.basedOnSize)
        .background(Color(red: 0.055, green: 0.045, blue: 0.095))
        .preferredColorScheme(.dark)
        .navigationTitle("Browser Relay").navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showQR) { QRView(link: link) }
        .onDisappear { inspection.cancel() }
    }

    private var dashboard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Behind the link").font(.title2.bold())
                Spacer()
                if inspection.busy { ProgressView().tint(violet) }
            }
            if let state = inspection.decision, state.complete {
                info(state.encrypted ? "Encrypted connection" : "Unencrypted hop in route",
                     state.encrypted ? "TLS accepted by iOS. This does not establish the site's trustworthiness." : "An HTTP request was sent without encryption.",
                     symbol: state.encrypted ? "lock.shield" : "lock.open", warning: !state.encrypted)
            } else {
                info(inspection.busy ? "Checking the destination…" : "Inspection incomplete",
                     "Only completed requests below have been checked.", symbol: "network")
            }
            if let message = inspection.message {
                info("Inspection stopped", message, symbol: "exclamationmark.triangle", warning: true)
            }
            if let state = inspection.decision, state.action == "consent", let destination = state.url {
                VStack(alignment: .leading, spacing: 10) {
                    Label("Another origin wants the link", systemImage: "arrow.triangle.turn.up.right.diamond")
                        .font(.headline).foregroundStyle(.orange)
                    Text(destination).font(.caption.monospaced()).textSelection(.enabled)
                    Text("Continue sends this address to that destination. Nothing has been sent there yet.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Continue inspection") { inspection.continueRedirect() }
                        .buttonStyle(.borderedProminent).tint(violet).disabled(inspection.busy)
                }.padding(16).background(panel, in: RoundedRectangle(cornerRadius: 18))
            }
            if let risk = inspection.risk {
                RiskPanel(risk: risk, tint: riskColor(risk.highest))
            }
            if let local = inspection.insights {
                HStack(alignment: .top, spacing: 10) {
                    info("OISD · Blocklist", listState(local.oisd.big, adult: false),
                         symbol: "shield.lefthalf.filled", tint: listColor(local.oisd.big, adult: false))
                    info("Adult content", listState(local.oisd.nsfw, adult: true),
                         symbol: "eye.slash", tint: listColor(local.oisd.nsfw, adult: true))
                }
                Text((local.oisd.stale == true ? "Stale lists · update in Data. " : "") + "Green means no list match. Site trust remains unknown.")
                    .font(.caption).foregroundStyle(.secondary)
                info(local.tranco.available == true ? (local.tranco.rank.map { "Tranco #\($0.formatted())" } ?? "Tranco · unranked") : "Tranco · no local data",
                     (local.tranco.stale == true ? "Stale data · " : "") + (local.tranco.caption ?? "Download the local ranking in the app's Data screen."),
                     symbol: "chart.bar", tint: rankColor(local.tranco.color))
                if let position = local.tranco.position {
                    GeometryReader { geometry in
                        Capsule().fill(LinearGradient(colors: [Color(red: 140/255, green: 221/255, blue: 165/255), Color(red: 1, green: 194/255, blue: 125/255), Color(red: 1, green: 137/255, blue: 149/255)], startPoint: .leading, endPoint: .trailing)).frame(height: 4).offset(y: 2)
                        Circle().fill(panel).overlay(Circle().stroke(.white, lineWidth: 1)).frame(width: 8, height: 8)
                            .offset(x: CGFloat(position) * max(0, geometry.size.width - 8))
                    }.frame(height: 8)
                    Text("0 · most popular                 1 · least popular / unranked")
                        .font(.caption2).foregroundStyle(.secondary)
                    Text("Log rank with arctangent smoothing. Popularity is not a safety score.")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            if !inspection.hops.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    Text("HTTP RESPONSE TIME").font(.caption.weight(.bold)).foregroundStyle(.secondary)
                    ForEach(inspection.hops) { hop in
                        HStack(spacing: 10) {
                            Text("\(hop.result.status)").font(.caption.monospaced()).frame(width: 32)
                            GeometryReader { geometry in
                                Capsule().fill(violet.gradient).frame(width: max(4, geometry.size.width * hop.result.milliseconds / maximumTime))
                            }.frame(height: 8)
                            Text("\(Int(hop.result.milliseconds)) ms").font(.caption.monospaced()).frame(width: 75, alignment: .trailing)
                        }.accessibilityElement(children: .combine)
                    }
                    Text("One HEAD request per hop, including connection setup. These are not ICMP ping probes.")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding(16).background(panel, in: RoundedRectangle(cornerRadius: 18))
            }
            if let last = inspection.hops.last {
                if let certificate = last.certificate {
                    info("Certificate", "Issued to: \(certificate.subject)\nSigned by: \(certificate.issuer)", symbol: "seal")
                }
                if let geo = last.geo {
                    info("\(geo.flag) \(geo.name)", last.result.peer ?? "Peer address unavailable", symbol: "globe")
                } else {
                    info(last.result.peer ?? "Peer address unavailable", "Import a local country MMDB in Data for approximate location. No online GeoIP fallback.", symbol: "globe")
                }
            }
            DisclosureGroup("Details & Privacy") {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Inspection uses iOS DNS and TLS through an ephemeral URLSession. No cookies, saved credentials, page scripts, Referer header or automatic redirects. The destination and your DNS/network provider can observe the request. Certificate network fetching is disabled for inspection. A CDN, proxy or VPN may obscure the server location.")
                    Text("The browser is separate: visiting a page runs its content normally, including third-party resources. iOS does not expose desktop browser discovery, direct DNS records or the Linux ICMP probe here. Optional online reputation and RDAP checks remain available on Linux only.")
                    if let local = inspection.insights {
                        Text(local.oisd.detail)
                        Text(local.tranco.detail)
                    }
                    ForEach(inspection.hops) { hop in
                        Divider()
                        Text(hop.url).font(.caption.monospaced())
                        if let cert = hop.certificate { Text(cert.detail) }
                        if let geo = hop.geo { Text(geo.detail) }
                    }
                }.font(.caption).textSelection(.enabled).padding(.top, 10)
            }.tint(violet).padding(16).background(panel, in: RoundedRectangle(cornerRadius: 18))
            HStack {
                Button("Check again") { inspection.start(link) }.disabled(inspection.busy)
                Spacer()
                if inspection.busy { Button("Stop") { inspection.cancel() } }
            }.buttonStyle(.bordered).tint(violet)
        }
    }

    private func listState(_ matched: Bool?, adult: Bool) -> String {
        guard let matched else { return "Unknown · no classification" }
        return matched ? (adult ? "Adult / shock match" : "Listed · ads, tracking or threats") : "No match"
    }
    private func listColor(_ matched: Bool?, adult: Bool) -> Color {
        guard let matched else { return .secondary }
        return matched ? (adult ? Color(red: 1, green: 194/255, blue: 125/255) : Color(red: 1, green: 137/255, blue: 149/255)) : Color(red: 140/255, green: 221/255, blue: 165/255)
    }
    private func riskColor(_ severity: String?) -> Color {
        switch severity {
        case "warning": return Color(red: 1, green: 137/255, blue: 149/255)
        case "caution": return Color(red: 1, green: 194/255, blue: 125/255)
        case "notice": return Color(red: 222/255, green: 203/255, blue: 1)
        default: return .secondary
        }
    }
    private func rankColor(_ rgb: [Double]?) -> Color {
        guard let rgb, rgb.count == 3 else { return .secondary }
        return Color(red: rgb[0] / 255, green: rgb[1] / 255, blue: rgb[2] / 255)
    }

    private var maximumTime: Double { max(1, inspection.hops.map { $0.result.milliseconds }.max() ?? 1) }

    private func info(_ title: String, _ detail: String, symbol: String, warning: Bool = false, tint: Color? = nil) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol).font(.subheadline.bold()).foregroundStyle(tint ?? (warning ? .orange : violet))
            Text(detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
            .background(panel, in: RoundedRectangle(cornerRadius: 18))
    }
}

struct QRView: View {
    let link: String
    @Environment(\.dismiss) private var dismiss
    private var code: QR? { try? Core.call(["op": "qr", "url": link]) }
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                if let code {
                    Canvas { context, size in
                        let count = code.width + 2 * code.quietZone
                        let pixel = floor(min(size.width, size.height) / CGFloat(count))
                        let offset = (size.width - pixel * CGFloat(count)) / 2
                        var path = Path()
                        for y in 0..<code.width {
                            for x in 0..<code.width where code.modules[y * code.width + x] {
                                path.addRect(CGRect(x: offset + CGFloat(x + code.quietZone) * pixel,
                                                    y: offset + CGFloat(y + code.quietZone) * pixel,
                                                    width: pixel, height: pixel))
                            }
                        }
                        context.fill(path, with: .color(.black))
                    }.aspectRatio(1, contentMode: .fit).frame(maxWidth: 330)
                        .background(.white, in: RoundedRectangle(cornerRadius: 16))
                        .accessibilityLabel("QR code for the selected link")
                    Text("Scan to open on another device").font(.headline)
                } else {
                    Image(systemName: "qrcode.viewfinder").font(.system(size: 56)).foregroundStyle(violet)
                    Text("A little too long for a compact QR").font(.title3.bold())
                    Text("Copy the link instead. The address is never shortened or sent to a QR service.")
                        .foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
            }.padding(28).navigationTitle("Show QR code").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }.preferredColorScheme(.dark)
    }
}

struct RiskPanel: View {
    let risk: RiskReport
    let tint: Color
    @State private var open: Set<String> = []
    @State private var seen: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Risk factors", systemImage: risk.highest == "warning" ? "exclamationmark.octagon.fill" : "list.bullet.rectangle")
                .font(.subheadline.bold()).foregroundStyle(tint)
            Text(risk.summary).font(.headline).foregroundStyle(tint)
            ForEach(risk.factors, id: \.self) { factor in
                DisclosureGroup(isExpanded: binding(factor)) {
                    VStack(alignment: .leading, spacing: 6) {
                        if let compare = factor.compare {
                            Text(highlighted("This link   ", compare.shown, compare.shownSpan)).font(.body.monospaced())
                            Text(highlighted("Looks like  ", compare.brand, compare.brandSpan)).font(.body.monospaced())
                        }
                        Text(factor.evidence).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                } label: {
                    HStack(alignment: .firstTextBaseline) {
                        Label(factor.title, systemImage: symbol(factor.severity)).font(.callout)
                        Spacer(minLength: 8)
                        Text(factor.word).font(.caption.bold()).foregroundStyle(severityColor(factor.severity))
                    }
                }
                .accessibilityLabel("\(factor.word): \(factor.title)")
            }
            if !risk.lookalikes {
                Text(risk.unavailable ?? "Lookalike checks are off. Download the ranking list in the app's Data screen.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Checked on this device. Finding none does not mean a site is safe.")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading).padding(16)
        .background(Color(red: 33/255, green: 30/255, blue: 43/255), in: RoundedRectangle(cornerRadius: 18))
        .onAppear(perform: seed).onChange(of: risk.factors) { _, _ in seed() }
    }

    private func key(_ f: RiskReport.Factor) -> String { f.id + "\u{1f}" + f.title }
    private func seed() {
        for f in risk.factors where seen.insert(key(f)).inserted && f.severity == "warning" { open.insert(key(f)) }
    }
    private func binding(_ f: RiskReport.Factor) -> Binding<Bool> {
        Binding(get: { open.contains(key(f)) }, set: { isOpen in
            if isOpen { open.insert(key(f)) } else { open.remove(key(f)) }
        })
    }
    private func severityColor(_ severity: String) -> Color {
        switch severity {
        case "warning": return Color(red: 1, green: 137/255, blue: 149/255)
        case "caution": return Color(red: 1, green: 194/255, blue: 125/255)
        default: return Color(red: 222/255, green: 203/255, blue: 1)
        }
    }
    private func symbol(_ severity: String) -> String {
        switch severity {
        case "warning": return "exclamationmark.octagon.fill"
        case "caution": return "exclamationmark.triangle.fill"
        default: return "info.circle"
        }
    }
    private func highlighted(_ lead: String, _ value: String, _ span: [Int]) -> AttributedString {
        let scalars = Array(value.unicodeScalars)
        let prefix = min(max(span.first ?? 0, 0), scalars.count)
        let end = max(prefix, min(max(scalars.count - (span.last ?? 0), 0), scalars.count))
        func text(_ slice: ArraySlice<Unicode.Scalar>) -> String { String(String.UnicodeScalarView(slice)) }
        var out = AttributedString(lead + text(scalars[..<prefix]))
        var diff = AttributedString(text(scalars[prefix..<end]))
        diff.foregroundColor = Color(red: 1, green: 194/255, blue: 125/255)
        diff.underlineStyle = Text.LineStyle.single
        diff.inlinePresentationIntent = .stronglyEmphasized
        out += diff
        out += AttributedString(text(scalars[end...]))
        return out
    }
}
