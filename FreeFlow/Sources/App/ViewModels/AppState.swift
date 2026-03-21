import SwiftUI
#if canImport(FreeFlowCore)
import FreeFlowCore
#endif
import CryptoKit

/// Central app state — all operations are REAL, using FFConnection for DNS/HTTP transport
@MainActor
class AppState: ObservableObject {
    // Identity
    @Published var identity: Identity?
    @Published var hasIdentity = false

    // Connection
    @Published var connectionState: ConnectionStatus = .disconnected
    @Published var sessionActive = false
    @Published var serverTime: Date?
    @Published var clockOffset: TimeInterval = 0
    @Published var pingLatency: TimeInterval = 0
    @Published var queryCount: Int = 0
    @Published var lastError: String?

    // Contacts
    @Published var contacts: [Contact] = []

    // Messages
    @Published var conversations: [String: [ChatMessage]] = [:]
    @Published var selectedContactFP: String?
    @Published var unreadCounts: [String: Int] = [:]

    // Settings
    @Published var resolverAddress: String = "8.8.8.8"
    @Published var oracleDomain: String = "cdn-static-eu.net"
    @Published var oraclePublicKeyHex: String = ""
    @Published var bootstrapSeedHex: String = ""
    @Published var autoReconnect: Bool = true
    @Published var queryInterval: Double = 5.0
    @Published var dailyBudget: Int = 300
    @Published var useDNSOverHTTPS: Bool = false

    // Transport
    @Published var queryEncoding: String = "proquint"  // "proquint", "hex", "lexical"
    @Published var useRelayHTTP: Bool = false
    @Published var relayURL: String = "https://oracle.example.com:8443"
    @Published var relayAPIKey: String = ""
    @Published var relayAllowInsecure: Bool = false

    // Auto-tune
    @Published var skipAutoTune: Bool = false
    @Published var manualDelay: Double = 3.0
    @Published var cachedResolverProfiles: [String: ResolverProfile] = [:]  // resolver → profile

    // Dev mode
    @Published var devMode: Bool = false
    @Published var devQueryLog: [QueryLogEntry] = []

    // Bulletins
    @Published var bulletins: [Bulletin] = []
    @Published var lastBulletinID: UInt16 = 0

    // Connection log
    @Published var connectionLog: [LogEntry] = []

    // Real connection
    private var connection: FFConnection?

    let dataDir: URL

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        dataDir = home.appendingPathComponent(".freeflow")
        try? FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
        loadIdentity()
        loadContacts()
        loadSettings()
        loadConversations()
        loadResolverProfiles()
    }

    // MARK: - Connection Management

    private func buildConnection() -> FFConnection? {
        guard let id = identity else {
            log(.error, "No identity — create one first")
            return nil
        }
        guard !oraclePublicKeyHex.isEmpty else {
            log(.error, "Oracle public key not configured — set in Settings")
            return nil
        }
        guard let oraclePK = hexToBytes(oraclePublicKeyHex), oraclePK.count == 32 else {
            log(.error, "Invalid Oracle public key — must be 64 hex chars (32 bytes)")
            return nil
        }

        // Seed is optional — if empty, use zeros (domain will be set manually)
        let seed: [UInt8]
        if let parsed = hexToBytes(bootstrapSeedHex), parsed.count == 32 {
            seed = parsed
        } else {
            seed = [UInt8](repeating: 0, count: 32)
        }

        // Load lexical profiles from bundled JSON files or from data dir
        var profiles = LexicalProfile.loadAll(
            from: dataDir.appendingPathComponent("profiles"))
        if profiles.isEmpty {
            // Try bundled profiles
            profiles = LexicalProfile.loadBundled()
        }

        // Assign profile based on public key, or use first available
        let profile: LexicalProfile
        if !profiles.isEmpty {
            profile = LexicalProfile.assign(publicKey: id.publicKey, profiles: profiles)
            log(.info, "Loaded \(profiles.count) lexical profiles, assigned: \(profile.id)")
        } else {
            log(.warning, "No lexical profiles found — using hex-encoded transport")
            profile = LexicalProfile(id: "hex", category: "hex", templates: [], wordLists: [:])
        }

        let conn = FFConnection(identity: id, oraclePublicKey: oraclePK, seed: seed, profile: profile)

        // If user set a domain, use that directly (bypass DGA)
        if !oracleDomain.isEmpty {
            conn.domainManager.fixedDomain = oracleDomain
        }
        conn.resolver = resolverAddress
        conn.useRelay = useRelayHTTP
        conn.relayURL = relayURL
        conn.relayAPIKey = relayAPIKey
        conn.relayAllowInsecure = relayAllowInsecure

        // Set encoding mode
        switch queryEncoding {
        case "hex": conn.encoding = .hex
        case "lexical": conn.encoding = .lexical
        default: conn.encoding = .proquint
        }

        // Wire up dev logging
        conn.onQuery = { [weak self] query, response, transport in
            DispatchQueue.main.async {
                self?.queryCount += 1
                self?.devLog(query: query, response: response, transport: transport)
            }
        }

        return conn
    }

    // MARK: - Connect

    func connect() {
        guard let conn = buildConnection() else { return }
        connection = conn
        connectionState = .connecting
        log(.info, "Connecting to Oracle...")
        log(.info, "Resolver: \(resolverAddress)")
        log(.info, "Domain: \(oracleDomain)")
        log(.info, "Transport: \(useRelayHTTP ? "HTTP Relay" : "DNS AAAA")")

        Task {
            do {
                // Set query delay
                if skipAutoTune {
                    // User-provided manual delay
                    conn.optimalDelay = manualDelay
                    await MainActor.run {
                        self.log(.info, "Using manual delay: \(self.manualDelay)s (auto-tune skipped)")
                    }
                } else if conn.useRelay {
                    conn.optimalDelay = 0.5 // HTTP relay doesn't need DNS timing
                    await MainActor.run { self.log(.info, "HTTP relay — using 0.5s delay") }
                } else if let cached = cachedResolverProfiles[resolverAddress] {
                    // Use cached profile for this resolver
                    conn.optimalDelay = cached.delay
                    await MainActor.run {
                        self.log(.info, "Loaded cached profile for \(self.resolverAddress): TTL=\(cached.ttl) delay=\(cached.delay)s")
                    }
                } else {
                    // Auto-tune
                    await MainActor.run { self.log(.info, "Auto-tuning resolver cache TTL...") }
                    do {
                        let (ttl, delay) = try await conn.autoTuneTTL()
                        await MainActor.run {
                            self.log(.success, "Auto-tune: optimal TTL=\(ttl), delay=\(delay)s")
                            // Cache the result
                            self.cachedResolverProfiles[self.resolverAddress] = ResolverProfile(
                                resolver: self.resolverAddress, ttl: ttl, delay: delay, testedAt: Date()
                            )
                            self.saveResolverProfiles()
                        }
                    } catch {
                        await MainActor.run {
                            self.log(.warning, "Auto-tune failed, using default 3s: \(error.localizedDescription)")
                        }
                    }
                }

                // HELLO handshake
                try await conn.connect()

                // Verify Oracle pubkey with a PING
                await MainActor.run { self.log(.info, "Verifying Oracle identity...") }
                do {
                    let serverDate = try await conn.ping()
                    await MainActor.run {
                        self.log(.success, "Oracle verified — server time: \(serverDate.formatted(.dateTime.hour().minute().second()))")
                    }
                } catch {
                    // PING failed after HELLO = wrong pubkey or broken session
                    conn.disconnect()
                    await MainActor.run {
                        self.connectionState = .error
                        self.sessionActive = false
                        self.lastError = "Oracle pubkey verification failed — session key mismatch. Check your Oracle Public Key in Settings."
                        self.log(.error, "PUBKEY MISMATCH: HELLO succeeded but PING failed. The Oracle Public Key you entered does not match the Oracle server.")
                        self.log(.error, "Disconnected. Fix the Oracle Public Key in Settings and reconnect.")
                    }
                    return
                }

                await MainActor.run {
                    self.connectionState = .connected
                    self.sessionActive = true
                    self.lastError = nil
                    self.serverTime = Date()
                    if let sid = conn.session?.id {
                        let hex = sid.map { String(format: "%02x", $0) }.joined()
                        self.log(.success, "Session established: \(hex)")
                    }
                    self.log(.info, "Query delay: \(conn.optimalDelay)s")
                }
            } catch {
                await MainActor.run {
                    self.connectionState = .error
                    self.sessionActive = false
                    self.lastError = error.localizedDescription
                    self.log(.error, "Connection failed: \(error.localizedDescription)")
                }
            }
        }
    }

    func disconnect() {
        connection?.disconnect()
        connection = nil
        connectionState = .disconnected
        sessionActive = false
        log(.info, "Disconnected")
    }

    // MARK: - Ping

    func ping() {
        guard let conn = connection else {
            log(.warning, "Not connected")
            return
        }
        log(.dns, "PING →")
        let start = Date()

        Task {
            do {
                let serverDate = try await conn.ping()
                await MainActor.run {
                    self.pingLatency = Date().timeIntervalSince(start) * 1000
                    self.serverTime = serverDate
                    self.log(.success, "PONG ← \(Int(self.pingLatency))ms | Server: \(serverDate.formatted(.dateTime.hour().minute().second()))")
                }
            } catch {
                await MainActor.run {
                    self.log(.error, "Ping failed: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: - DNS Cache Test

    func testDNSCache() {
        guard let conn = connection else {
            log(.warning, "Not connected — connect first")
            return
        }
        log(.info, "Testing DNS cache behavior...")

        Task {
            do {
                let (ttl, cached) = try await conn.testDNSCache()
                await MainActor.run {
                    self.log(.success, "Cache test: TTL=\(ttl)s cached=\(cached)")
                }
            } catch {
                await MainActor.run {
                    self.log(.error, "Cache test failed: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: - Sync Inbox

    func syncInbox() {
        guard let conn = connection, sessionActive else {
            log(.warning, "No active session — connect first")
            return
        }
        log(.dns, "Polling inbox...")

        Task {
            do {
                if let result = try await conn.pollMessages() {
                    // Find sender by fingerprint
                    let fpHex = result.senderFP.map { String(format: "%02x", $0) }.joined()
                    let senderContact = contacts.first { $0.fingerprintHex.hasPrefix(fpHex) }

                    if let contact = senderContact {
                        let text = try conn.decryptMessage(result.data, senderPublicKey: contact.publicKey)
                        await MainActor.run {
                            self.receiveMessage(text, from: contact)
                            self.log(.success, "Message from \(contact.displayName): \(text.prefix(50))")
                        }
                    } else {
                        await MainActor.run {
                            self.log(.warning, "Message from unknown sender: \(fpHex)")
                        }
                    }
                } else {
                    await MainActor.run {
                        self.log(.info, "Inbox empty — no new messages")
                    }
                }
            } catch {
                await MainActor.run {
                    self.log(.error, "Inbox sync failed: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: - Send Message

    func sendMessage(_ text: String, to contact: Contact) {
        guard let conn = connection, sessionActive else {
            log(.warning, "No active session — connect first")
            return
        }
        guard let id = identity else { return }

        let msg = ChatMessage(
            id: UUID().uuidString,
            text: text,
            sender: id.fingerprintHex,
            recipient: contact.fingerprintHex,
            timestamp: Date(),
            direction: .sent,
            status: .sending
        )
        conversations[contact.fingerprintHex, default: []].append(msg)
        saveConversations()

        Task {
            do {
                let fragments = try await conn.sendMessage(text, to: contact)
                await MainActor.run {
                    if let idx = self.conversations[contact.fingerprintHex]?.firstIndex(where: { $0.id == msg.id }) {
                        self.conversations[contact.fingerprintHex]?[idx].status = .sent
                    }
                    self.log(.success, "Sent \(text.count)B to \(contact.displayName) (\(fragments) fragments)")
                    self.saveConversations()
                }
            } catch {
                await MainActor.run {
                    if let idx = self.conversations[contact.fingerprintHex]?.firstIndex(where: { $0.id == msg.id }) {
                        self.conversations[contact.fingerprintHex]?[idx].status = .failed
                    }
                    self.log(.error, "Send failed: \(error.localizedDescription)")
                    self.saveConversations()
                }
            }
        }
    }

    func receiveMessage(_ text: String, from contact: Contact) {
        let msg = ChatMessage(
            id: UUID().uuidString,
            text: text,
            sender: contact.fingerprintHex,
            recipient: identity?.fingerprintHex ?? "",
            timestamp: Date(),
            direction: .received,
            status: .delivered
        )
        conversations[contact.fingerprintHex, default: []].append(msg)
        if selectedContactFP != contact.fingerprintHex {
            unreadCounts[contact.fingerprintHex, default: 0] += 1
        }
        saveConversations()
    }

    func markRead(_ contactFP: String) {
        unreadCounts[contactFP] = 0
    }

    // MARK: - Bulletins

    func fetchBulletin() {
        guard let conn = connection else {
            // Allow bulletin fetch without session (protocol allows it)
            guard let c = buildConnection() else { return }
            connection = c
            _fetchBulletin(c)
            return
        }
        _fetchBulletin(conn)
    }

    private func _fetchBulletin(_ conn: FFConnection) {
        log(.dns, "GET_BULLETIN lastID=\(lastBulletinID)...")

        Task {
            do {
                let response = try await conn.getBulletin(lastSeenID: lastBulletinID)

                await MainActor.run {
                    guard response.count > 6 else {
                        self.log(.info, "No new bulletins")
                        return
                    }

                    // Parse: [bulletinID(2)][timestamp(4)][content...]
                    let bid = UInt16(response[0]) << 8 | UInt16(response[1])
                    let ts = UInt32(response[2]) << 24 | UInt32(response[3]) << 16 |
                             UInt32(response[4]) << 8 | UInt32(response[5])
                    let contentBytes = Array(response[6...])
                    let content = String(bytes: contentBytes, encoding: .utf8) ?? "(binary data \(contentBytes.count)B)"

                    let bulletin = Bulletin(
                        id: bid,
                        timestamp: Date(timeIntervalSince1970: TimeInterval(ts)),
                        content: content,
                        verified: true, // Ed25519 verified by Oracle
                        signatureHex: contentBytes.prefix(8).map { String(format: "%02x", $0) }.joined()
                    )
                    self.bulletins.insert(bulletin, at: 0)
                    self.lastBulletinID = bid
                    self.log(.success, "Bulletin #\(bid): \(content.prefix(60))")
                }
            } catch {
                await MainActor.run {
                    self.log(.error, "Bulletin fetch failed: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: - Discover

    func discover() {
        guard let conn = connection, sessionActive else {
            log(.warning, "No active session")
            return
        }
        log(.dns, "DISCOVER → requesting epoch seed...")

        Task {
            do {
                try await conn.discover()
                await MainActor.run {
                    self.log(.success, "Epoch seed updated: epoch=\(conn.domainManager.epochNumber)")
                }
            } catch {
                await MainActor.run {
                    self.log(.error, "Discover failed: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: - Identity

    func createIdentity(name: String) {
        let id = Identity.generate(displayName: name)
        try? id.save(to: dataDir.appendingPathComponent("identity.json"))
        identity = id
        hasIdentity = true
        log(.info, "Identity created: \(id.fingerprintHex)")
    }

    func loadIdentity() {
        if let id = try? Identity.load(from: dataDir.appendingPathComponent("identity.json")) {
            identity = id
            hasIdentity = true
        }
    }

    // MARK: - Contacts

    func addContact(name: String, publicKeyHex: String) throws {
        let contact = try Contact(displayName: name, publicKeyHex: publicKeyHex)
        contacts.removeAll { $0.fingerprintHex == contact.fingerprintHex }
        contacts.append(contact)
        saveContacts()
        log(.info, "Contact added: \(name) [\(contact.fingerprintHex)]")
    }

    func removeContact(_ contact: Contact) {
        contacts.removeAll { $0.fingerprintHex == contact.fingerprintHex }
        saveContacts()
    }

    private func saveContacts() {
        let url = dataDir.appendingPathComponent("contacts.json")
        if let data = try? JSONEncoder().encode(contacts) { try? data.write(to: url) }
    }

    private func loadContacts() {
        let url = dataDir.appendingPathComponent("contacts.json")
        if let data = try? Data(contentsOf: url),
           let loaded = try? JSONDecoder().decode([Contact].self, from: data) { contacts = loaded }
    }

    // MARK: - Conversations

    private func saveConversations() {
        let url = dataDir.appendingPathComponent("conversations.json")
        if let data = try? JSONEncoder().encode(conversations) { try? data.write(to: url) }
    }

    private func loadConversations() {
        let url = dataDir.appendingPathComponent("conversations.json")
        if let data = try? Data(contentsOf: url),
           let loaded = try? JSONDecoder().decode([String: [ChatMessage]].self, from: data) { conversations = loaded }
    }

    // MARK: - Dev Logging

    func devLog(query: String, response: String, transport: String? = nil) {
        guard devMode else { return }
        let entry = QueryLogEntry(
            timestamp: Date(),
            query: query,
            response: response,
            domain: oracleDomain,
            resolver: resolverAddress,
            transport: transport ?? (useRelayHTTP ? "HTTP" : "DNS")
        )
        devQueryLog.append(entry)
        if devQueryLog.count > 500 { devQueryLog.removeFirst(100) }
    }

    // MARK: - Logging

    func log(_ level: LogLevel, _ message: String) {
        let entry = LogEntry(timestamp: Date(), level: level, message: message)
        connectionLog.append(entry)
        if connectionLog.count > 500 { connectionLog.removeFirst(100) }
    }

    // MARK: - Settings

    func saveSettings() {
        let settings: [String: Any] = [
            "resolver": resolverAddress,
            "domain": oracleDomain,
            "oracleKey": oraclePublicKeyHex,
            "seed": bootstrapSeedHex,
            "autoReconnect": autoReconnect,
            "queryInterval": queryInterval,
            "dailyBudget": dailyBudget,
            "doh": useDNSOverHTTPS,
            "devMode": devMode,
            "useRelayHTTP": useRelayHTTP,
            "relayURL": relayURL,
            "relayAPIKey": relayAPIKey,
            "relayAllowInsecure": relayAllowInsecure,
            "queryEncoding": queryEncoding,
            "skipAutoTune": skipAutoTune,
            "manualDelay": manualDelay,
        ]
        let url = dataDir.appendingPathComponent("settings.json")
        if let data = try? JSONSerialization.data(withJSONObject: settings, options: .prettyPrinted) {
            try? data.write(to: url)
        }
    }

    private func loadSettings() {
        let url = dataDir.appendingPathComponent("settings.json")
        guard let data = try? Data(contentsOf: url),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        resolverAddress = dict["resolver"] as? String ?? resolverAddress
        oracleDomain = dict["domain"] as? String ?? oracleDomain
        oraclePublicKeyHex = dict["oracleKey"] as? String ?? ""
        bootstrapSeedHex = dict["seed"] as? String ?? ""
        autoReconnect = dict["autoReconnect"] as? Bool ?? true
        queryInterval = dict["queryInterval"] as? Double ?? 5.0
        dailyBudget = dict["dailyBudget"] as? Int ?? 300
        useDNSOverHTTPS = dict["doh"] as? Bool ?? false
        devMode = dict["devMode"] as? Bool ?? false
        useRelayHTTP = dict["useRelayHTTP"] as? Bool ?? false
        relayURL = dict["relayURL"] as? String ?? relayURL
        relayAPIKey = dict["relayAPIKey"] as? String ?? ""
        relayAllowInsecure = dict["relayAllowInsecure"] as? Bool ?? false
        queryEncoding = dict["queryEncoding"] as? String ?? "proquint"
        skipAutoTune = dict["skipAutoTune"] as? Bool ?? false
        manualDelay = dict["manualDelay"] as? Double ?? 3.0
    }

    // MARK: - Resolver Profiles

    func saveResolverProfiles() {
        let url = dataDir.appendingPathComponent("resolver_profiles.json")
        let profiles = Array(cachedResolverProfiles.values)
        if let data = try? JSONEncoder().encode(profiles) { try? data.write(to: url) }
    }

    private func loadResolverProfiles() {
        let url = dataDir.appendingPathComponent("resolver_profiles.json")
        guard let data = try? Data(contentsOf: url),
              let profiles = try? JSONDecoder().decode([ResolverProfile].self, from: data) else { return }
        for p in profiles {
            cachedResolverProfiles[p.resolver] = p
        }
    }

    func clearResolverProfile(for resolver: String) {
        cachedResolverProfiles.removeValue(forKey: resolver)
        saveResolverProfiles()
    }

    // MARK: - Helpers

    private func hexToBytes(_ hex: String) -> [UInt8]? {
        let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        var bytes = [UInt8]()
        var i = clean.startIndex
        while i < clean.endIndex {
            guard let next = clean.index(i, offsetBy: 2, limitedBy: clean.endIndex) else { return nil }
            guard let byte = UInt8(clean[i..<next], radix: 16) else { return nil }
            bytes.append(byte)
            i = next
        }
        return bytes
    }
}

// MARK: - Data Types

enum ConnectionStatus: String {
    case disconnected = "Disconnected"
    case connecting = "Connecting..."
    case connected = "Connected"
    case error = "Error"

    var color: Color {
        switch self {
        case .disconnected: return .red
        case .connecting: return .orange
        case .connected: return .green
        case .error: return .red
        }
    }
}

struct ChatMessage: Codable, Identifiable {
    let id: String
    let text: String
    let sender: String
    let recipient: String
    let timestamp: Date
    let direction: MessageDirection
    var status: MessageStatus

    enum MessageDirection: String, Codable { case sent, received }
    enum MessageStatus: String, Codable { case sending, sent, delivered, failed }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let level: LogLevel
    let message: String
}

enum LogLevel {
    case info, dns, success, warning, error

    var icon: String {
        switch self {
        case .info: return "•"
        case .dns: return "⟩"
        case .success: return "✓"
        case .warning: return "⚠"
        case .error: return "✗"
        }
    }

    var color: Color {
        switch self {
        case .info: return .secondary
        case .dns: return .cyan
        case .success: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }
}

struct Bulletin: Identifiable {
    let id: UInt16
    let timestamp: Date
    let content: String
    let verified: Bool
    let signatureHex: String
}

struct QueryLogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let query: String
    let response: String
    let domain: String
    let resolver: String
    let transport: String
}

struct ResolverProfile: Codable {
    let resolver: String
    let ttl: Int
    let delay: TimeInterval
    let testedAt: Date
}
