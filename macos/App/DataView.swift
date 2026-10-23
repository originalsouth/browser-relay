import SwiftUI
import UniformTypeIdentifiers

struct DataView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var confirm = false
    @State private var confirmCT = false
    @State private var ctDisclosure = ""
    @State private var importing = false
    @State private var busy = false
    @State private var status = "No background downloads. You choose when the local data changes."
    @State private var task: Task<Void, Never>?
    var body: some View {
        NavigationStack {
            Form {
                Section("Local reputation") {
                    Text("OISD blocklists and Tranco rankings, including subdomains. Matching happens on your device.")
                    Button("Download / update lists") { confirm = true }.disabled(busy)
                    if busy { ProgressView() }
                    Text(status).font(.footnote).foregroundStyle(.secondary)
                }
                Section("Certificate Transparency") {
                    Text("Refresh the signed log keys used by local certificate checks.")
                    Button("Update log keys…") {
                        do {
                            let sources: CTSources = try Core.call(["op": "ct_sources"])
                            ctDisclosure = sources.disclosure
                            confirmCT = true
                        } catch { status = error.localizedDescription }
                    }.disabled(busy)
                }
                Section("Local GeoIP") {
                    Text("Import a country MMDB database under 16 MiB. Coordinates identify an approximate network location, not a person.")
                    Button("Import MMDB…") { importing = true }
                    Text("Use data you are licensed to use. DB-IP Lite requires attribution: DB-IP.com, CC BY 4.0.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Privacy") {
                    Text("List updates contact big.oisd.nl, nsfw.oisd.nl and tranco-list.eu. Publishers see your network address and requests for their public datasets. Your inspected addresses are never included. These downloads need no account or API key. CT key updates contact www.gstatic.com for two public signed-metadata files, without sending an inspected link.")
                    Text("Indexes and imported GeoIP data stay in this Mac’s Application Support/BrowserRelay folder.")
                }
            }.formStyle(.grouped).navigationTitle("Local data")
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
                .confirmationDialog("Download public datasets?", isPresented: $confirm, titleVisibility: .visible) {
                    Button("Download from OISD and Tranco") { update() }
                } message: { Text("Contacts OISD and Tranco, without sending any inspected link. Downloads may total tens of megabytes. Existing indexes are replaced only after validation.") }
                .confirmationDialog("Update CT log keys?", isPresented: $confirmCT, titleVisibility: .visible) {
                    Button("Download signed log keys") {
                        busy = true
                        task = Task {
                            do { status = try await Storage.updateCT() }
                            catch { status = error.localizedDescription }
                            busy = false
                        }
                    }
                } message: { Text(ctDisclosure) }
                .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
                    do { try Storage.importGeo(result.get()); status = "Local GeoIP database imported." }
                    catch { status = error.localizedDescription }
                }
                .onDisappear { task?.cancel() }
        }.preferredColorScheme(.dark)
    }
    private func update() {
        busy = true
        task = Task {
            do { try await Storage.updateLists { status = $0 } }
            catch { status += "\n" + error.localizedDescription }
            busy = false
        }
    }
}
