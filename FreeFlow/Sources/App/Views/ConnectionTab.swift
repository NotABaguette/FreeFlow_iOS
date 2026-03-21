import SwiftUI

struct ConnectionTab: View {
    @EnvironmentObject var state: AppState
    @State private var showDevLog = false

    var body: some View {
        NavigationStack {
            List {
                // Status
                Section {
                    HStack {
                        Circle().fill(state.connectionState.color).frame(width: 12, height: 12)
                        Text(state.connectionState.rawValue)
                            .font(.system(.body, design: .monospaced)).bold()
                        Spacer()
                        Text("\(state.queryCount) queries")
                            .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    if state.pingLatency > 0 {
                        LabeledContent("Latency") { Text("\(Int(state.pingLatency))ms") }
                    }
                    if let t = state.serverTime {
                        LabeledContent("Server Time") { Text(t, style: .time) }
                    }
                    if state.sessionActive {
                        LabeledContent("Session") { Text("Active").foregroundColor(.green) }
                        LabeledContent("Transport") {
                            Text(state.useRelayHTTP ? "HTTP Relay" : "DNS (\(state.queryEncoding))")
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                }

                // Actions
                Section("Actions") {
                    Button {
                        if state.connectionState == .connected { state.disconnect() }
                        else { state.connect() }
                    } label: {
                        Label(state.connectionState == .connected ? "Disconnect" : "Connect",
                              systemImage: state.connectionState == .connected ? "xmark.circle" : "bolt.circle")
                        .foregroundColor(state.connectionState == .connected ? .red : .blue)
                    }

                    Button { state.ping() } label: {
                        Label("Ping", systemImage: "wave.3.right")
                    }

                    Button { state.testDNSCache() } label: {
                        Label("Cache Test", systemImage: "cylinder")
                    }

                    Button { state.discover() } label: {
                        Label("Discover", systemImage: "arrow.triangle.2.circlepath")
                    }.disabled(!state.sessionActive)
                }

                // Config
                Section("Configuration") {
                    HStack {
                        Text("Resolver")
                        Spacer()
                        TextField("8.8.8.8", text: $state.resolverAddress)
                            .font(.system(.body, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                    }
                    HStack {
                        Text("Domain")
                        Spacer()
                        TextField("domain.com", text: $state.oracleDomain)
                            .font(.system(.body, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                    }
                    Toggle("Skip Auto-Tune", isOn: $state.skipAutoTune)
                    if state.skipAutoTune {
                        HStack {
                            Text("Manual Delay")
                            Spacer()
                            TextField("3", value: $state.manualDelay, format: .number)
                                .frame(width: 50).multilineTextAlignment(.trailing)
                            Text("sec").foregroundStyle(.secondary)
                        }
                    }
                }

                // Connection Log
                Section("Log") {
                    ForEach(state.connectionLog.suffix(20)) { entry in
                        HStack(spacing: 6) {
                            Text(entry.level.icon).foregroundColor(entry.level.color).frame(width: 14)
                            Text(entry.message).font(.system(.caption, design: .monospaced))
                                .foregroundColor(entry.level == .info ? .primary : entry.level.color)
                        }
                    }
                }

                if state.devMode {
                    Section("Dev Query Log") {
                        ForEach(state.devQueryLog.suffix(15)) { entry in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(entry.timestamp, style: .time).foregroundStyle(.tertiary)
                                    Text("[\(entry.transport)]").foregroundColor(.purple)
                                }.font(.system(.caption2, design: .monospaced))
                                Text("Q: \(entry.query)").font(.system(.caption2, design: .monospaced)).foregroundColor(.orange)
                                Text("R: \(entry.response)").font(.system(.caption2, design: .monospaced)).foregroundColor(.green)
                            }.padding(.vertical, 2)
                        }
                    }
                }

                if let err = state.lastError {
                    Section("Error") {
                        Text(err).font(.system(.caption, design: .monospaced)).foregroundColor(.red)
                    }
                }
            }
            .navigationTitle("Connection")
        }
    }
}
