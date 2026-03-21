import SwiftUI

struct SettingsTab: View {
    @EnvironmentObject var state: AppState
    @State private var newName = ""
    @State private var copied = false

    var body: some View {
        NavigationStack {
            Form {
                // Identity
                if let id = state.identity {
                    Section("Identity") {
                        HStack {
                            ZStack {
                                Circle().fill(.blue.gradient).frame(width: 50, height: 50)
                                Text(String(id.displayName.prefix(1)).uppercased())
                                    .font(.title2).foregroundStyle(.white).bold()
                            }
                            VStack(alignment: .leading) {
                                Text(id.displayName).font(.system(.body, design: .monospaced)).bold()
                                Text(id.fingerprintHex)
                                    .font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                            }
                        }
                        Button {
                            UIPasteboard.general.string = id.publicKey.map { String(format: "%02x", $0) }.joined()
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                        } label: {
                            Label(copied ? "Copied!" : "Copy Public Key", systemImage: copied ? "checkmark" : "doc.on.doc")
                        }
                    }
                } else {
                    Section("Create Identity") {
                        TextField("Your name", text: $newName)
                            .font(.system(.body, design: .monospaced))
                        Button {
                            state.createIdentity(name: newName.isEmpty ? "Anonymous" : newName)
                        } label: {
                            Label("Generate Identity", systemImage: "key")
                        }.buttonStyle(.borderedProminent)
                    }
                }

                // Oracle
                Section("Oracle") {
                    HStack {
                        Text("Domain")
                        Spacer()
                        TextField("domain.com", text: $state.oracleDomain)
                            .font(.system(.caption, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                    }
                    VStack(alignment: .leading) {
                        Text("Oracle Public Key").font(.caption).foregroundStyle(.secondary)
                        TextEditor(text: $state.oraclePublicKeyHex)
                            .font(.system(.caption2, design: .monospaced))
                            .frame(minHeight: 40)
                    }
                    VStack(alignment: .leading) {
                        Text("Bootstrap Seed (optional)").font(.caption).foregroundStyle(.secondary)
                        TextEditor(text: $state.bootstrapSeedHex)
                            .font(.system(.caption2, design: .monospaced))
                            .frame(minHeight: 40)
                    }
                }

                // Transport
                Section("Transport") {
                    Picker("Mode", selection: $state.useRelayHTTP) {
                        Text("DNS").tag(false)
                        Text("HTTP Relay").tag(true)
                    }.pickerStyle(.segmented)

                    if !state.useRelayHTTP {
                        Picker("Encoding", selection: $state.queryEncoding) {
                            Text("Proquint").tag("proquint")
                            Text("Hex").tag("hex")
                            Text("Lexical").tag("lexical")
                        }
                    } else {
                        HStack {
                            Text("Relay URL")
                            Spacer()
                            TextField("https://...", text: $state.relayURL)
                                .font(.system(.caption, design: .monospaced))
                                .multilineTextAlignment(.trailing)
                        }
                        HStack {
                            Text("API Key")
                            Spacer()
                            TextField("key", text: $state.relayAPIKey)
                                .font(.system(.caption, design: .monospaced))
                                .multilineTextAlignment(.trailing)
                        }
                        Toggle("Allow Insecure HTTP", isOn: $state.relayAllowInsecure)
                        if state.relayAllowInsecure {
                            Text("WARNING: Traffic not encrypted in transit")
                                .font(.caption).foregroundColor(.red)
                        }
                    }
                }

                // Network
                Section("Network") {
                    HStack {
                        Text("Resolver")
                        Spacer()
                        TextField("8.8.8.8", text: $state.resolverAddress)
                            .font(.system(.body, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                    }
                    Toggle("Auto-reconnect", isOn: $state.autoReconnect)
                }

                // Developer
                Section("Developer") {
                    Toggle("Dev Mode", isOn: $state.devMode)
                    if state.devMode {
                        Text("All queries logged in Connection tab")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                // Crypto Info
                Section("Encryption") {
                    LabeledContent("Key Exchange") { Text("X25519").font(.caption) }
                    LabeledContent("Cipher") { Text("ChaCha20-Poly1305").font(.caption) }
                    LabeledContent("KDF") { Text("HKDF-SHA256").font(.caption) }
                    LabeledContent("Signatures") { Text("Ed25519").font(.caption) }
                }

                Section("About") {
                    LabeledContent("Version") { Text("1.0.0") }
                    LabeledContent("Protocol") { Text("FreeFlow v2.1") }
                }
            }
            .navigationTitle("Settings")
            .onChange(of: state.oracleDomain) { _, _ in state.saveSettings() }
            .onChange(of: state.oraclePublicKeyHex) { _, _ in state.saveSettings() }
            .onChange(of: state.useRelayHTTP) { _, _ in state.saveSettings() }
            .onChange(of: state.queryEncoding) { _, _ in state.saveSettings() }
            .onChange(of: state.devMode) { _, _ in state.saveSettings() }
        }
    }
}
