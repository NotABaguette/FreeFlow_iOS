import SwiftUI

struct BulletinsTab: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            List {
                ForEach(state.bulletins) { bulletin in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("BULLETIN #\(bulletin.id)")
                                .font(.system(.caption, design: .monospaced)).bold()
                                .foregroundColor(.orange)
                            Spacer()
                            if bulletin.verified {
                                Label("Verified", systemImage: "checkmark.shield.fill")
                                    .font(.system(.caption2, design: .monospaced)).foregroundColor(.green)
                            }
                            Text(bulletin.timestamp, style: .relative)
                                .font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                        }
                        Text(bulletin.content)
                            .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        Text("Sig: \(bulletin.signatureHex)...")
                            .font(.system(.caption2, design: .monospaced)).foregroundStyle(.tertiary)
                    }.padding(.vertical, 4)
                }
            }
            .navigationTitle("Bulletins")
            .toolbar {
                Button { state.fetchBulletin() } label: {
                    Label("Fetch", systemImage: "arrow.clockwise")
                }
            }
            .overlay {
                if state.bulletins.isEmpty {
                    ContentUnavailableView("No Bulletins", systemImage: "megaphone",
                        description: Text("Tap fetch to check for broadcasts"))
                }
            }
        }
    }
}
