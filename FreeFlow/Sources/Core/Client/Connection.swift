import Foundation
import Network
import CryptoKit

/// Main FreeFlow client connection — handles all protocol operations over DNS or HTTP relay
public class FFConnection: ObservableObject {
    @Published public var state: ConnectionState = .disconnected
    @Published public var session: FFSession?

    public let identity: Identity
    public let domainManager: DomainManager
    public let rateLimiter = AdaptiveRateLimiter()
    public var profile: LexicalProfile
    public var oraclePublicKey: [UInt8]

    public var resolver: String = "8.8.8.8"
    public var useRelay: Bool = false
    public var relayURL: String = ""
    public var relayAPIKey: String = ""
    public var relayAllowInsecure: Bool = false

    /// Called for every query/response when set (for dev logging)
    public var onQuery: ((_ query: String, _ response: String, _ transport: String) -> Void)?

    public enum ConnectionState: String {
        case disconnected, connecting, connected, dormant
    }

    public init(identity: Identity, oraclePublicKey: [UInt8], seed: [UInt8], profile: LexicalProfile) {
        self.identity = identity
        self.oraclePublicKey = oraclePublicKey
        self.domainManager = DomainManager(seed: seed)
        self.profile = profile
    }

    // MARK: - PING

    public func ping() async throws -> Date {
        // PING: full frame for proquint (needs ≥4 bytes = 2 words),
        // compact for lexical encoding
        let payload: [UInt8]
        if encoding == .lexical {
            payload = [Command.ping.rawValue]
        } else {
            payload = QueryPayload(command: Command.ping.rawValue).toFrame()
        }
        onQuery?("PING cmd=0x07", "sending...", transport)
        let response = try await checkErrorResponse(try await queryOracle(payload: payload))
        guard response.count >= 4 else { throw FFError.frameTooShort(response.count) }
        let serverTime = UInt32(response[0]) << 24 | UInt32(response[1]) << 16 |
                         UInt32(response[2]) << 8 | UInt32(response[3])
        let date = Date(timeIntervalSince1970: TimeInterval(serverTime))
        domainManager.syncClock(serverTime: serverTime)
        onQuery?("PING cmd=0x07", "PONG server_time=\(serverTime)", transport)
        return date
    }

    // MARK: - HELLO

    public func connect() async throws {
        state = .connecting
        let ephemeral = KeyPair()
        let pubBytes = ephemeral.publicKeyBytes
        let helloNonce = UInt16.random(in: 0...UInt16.max)

        for i in 0..<4 {
            let chunk = Array(pubBytes[(i*8)..<((i+1)*8)])

            // Build HELLO frame matching Go's BuildHelloChunkPayload:
            // Data: [chunkIdx][totalChunks][nonce_hi][nonce_lo][8_bytes]
            var data: [UInt8] = [UInt8(i), 4]
            data.append(UInt8((helloNonce >> 8) & 0xFF))
            data.append(UInt8(helloNonce & 0xFF))
            data.append(contentsOf: chunk)

            // Frame: [cmd=0x01][seqNo=i][fragIdx=i][fragTotal=4][token=0000][data]
            let frame = QueryPayload(
                command: Command.hello.rawValue,
                seqNo: UInt8(i),
                fragIndex: UInt8(i),
                fragTotal: 4,
                data: data
            ).toFrame()

            let chunkHex = chunk.map { String(format: "%02x", $0) }.joined()
            onQuery?("HELLO chunk=\(i)/4 nonce=\(helloNonce) data=\(chunkHex)", "sending \(frame.count)B frame...", transport)

            let response = try await checkErrorResponse(try await queryOracle(payload: frame))

            if i == 3 {
                let sharedSecret = try ephemeral.sharedSecret(with: oraclePublicKey)
                let sessionKeyBytes = FFSession.deriveKey(sharedSecret: sharedSecret)
                let sessionID = try FFSession.decodeHelloComplete(
                    response: response, sessionKey: sessionKeyBytes)

                session = FFSession(id: sessionID, keyBytes: sessionKeyBytes)
                let sidHex = sessionID.map { String(format: "%02x", $0) }.joined()
                onQuery?("HELLO_COMPLETE", "session_id=\(sidHex) key_derived=32B", transport)

                // Auto-REGISTER after HELLO (matches Go client flow)
                try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
                try await register()

                state = .connected
            } else {
                onQuery?("HELLO chunk=\(i)/4", "ACK chunk_idx=\(i)", transport)
                try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
            }
        }
    }

    public func disconnect() {
        state = .disconnected
        session = nil
        onQuery?("DISCONNECT", "session destroyed", transport)
    }

    // MARK: - REGISTER

    /// Register persistent identity with the session (§4.4).
    /// Fragmented into 3 queries for proquint (each ≤20 bytes).
    /// Single query for hex encoding (40 bytes = 2 labels).
    /// Oracle computes fingerprint = SHA256(pubkey)[0:8] itself.
    /// Client MUST verify returned fingerprint matches local computation.
    public func register() async throws {
        guard let sess = session else { throw FFError.noSession }

        let pubkey = identity.publicKey // 32 bytes

        if encoding == .proquint {
            // §4.4 Fragmented format: 3 queries, each ≤20 bytes
            // Fragment 0: pubkey[0..11]  (12 bytes data, frame=20)
            // Fragment 1: pubkey[12..23] (12 bytes data, frame=20)
            // Fragment 2: pubkey[24..31] (8 bytes data, frame=16)
            let chunks: [[UInt8]] = [
                Array(pubkey[0..<12]),
                Array(pubkey[12..<24]),
                Array(pubkey[24..<32]),
            ]

            for (i, chunk) in chunks.enumerated() {
                let seq = sess.nextSeqNo()
                let token = sess.token(for: seq)

                let frame = QueryPayload(
                    command: 0x08,
                    seqNo: UInt8(seq & 0xFF),
                    fragIndex: UInt8(i),
                    fragTotal: UInt8(chunks.count),
                    sessionToken: token,
                    data: chunk
                ).toFrame()

                onQuery?("REGISTER frag=\(i+1)/\(chunks.count) \(chunk.count)B", "sending \(frame.count)B frame...", transport)
                let response = try await checkErrorResponse(try await queryOracle(payload: frame))

                if i == chunks.count - 1 {
                    verifyRegisterResponse(response)
                }

                if i < chunks.count - 1 {
                    try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
                }
            }
        } else {
            // Single-query format: 40 bytes (header=8 + pubkey=32)
            let seq = sess.nextSeqNo()
            let token = sess.token(for: seq)

            let frame = QueryPayload(
                command: 0x08,
                seqNo: UInt8(seq & 0xFF),
                fragIndex: 0,
                fragTotal: 1,
                sessionToken: token,
                data: pubkey
            ).toFrame()

            onQuery?("REGISTER single-query 40B", "sending...", transport)
            let response = try await checkErrorResponse(try await queryOracle(payload: frame))
            verifyRegisterResponse(response)
        }
    }

    /// Verify Oracle-returned fingerprint matches local computation (§4.4)
    private func verifyRegisterResponse(_ response: [UInt8]) {
        if response.count >= 8 {
            let oracleFP = response.prefix(8).map { String(format: "%02x", $0) }.joined()
            let localFP = identity.fingerprintHex
            if oracleFP == localFP {
                onQuery?("REGISTER", "OK — fingerprint verified: \(oracleFP)", transport)
            } else {
                onQuery?("REGISTER", "WARNING — fingerprint mismatch! Oracle=\(oracleFP) Local=\(localFP)", transport)
            }
        }
    }

    /// Check for 0xFF error responses from Oracle (§3.2)
    private func checkErrorResponse(_ response: [UInt8]) throws -> [UInt8] {
        if response.count >= 2 && response[0] == 0xFF {
            let code = response[1]
            let errorNames: [UInt8: String] = [
                0x00: "Unknown", 0x01: "NoSession", 0x02: "InvalidToken",
                0x03: "RateLimit", 0x04: "Malformed", 0x05: "NoBulletin",
                0x06: "NoMessage", 0x07: "HelloTimeout", 0x08: "HelloConflict"
            ]
            let name = errorNames[code] ?? "0x\(String(format: "%02x", code))"
            throw FFError.helloFailed("Oracle error: \(name)")
        }
        return response
    }

    // MARK: - GET BULLETIN

    public func getBulletin(lastSeenID: UInt16 = 0) async throws -> [UInt8] {
        let frame: [UInt8]
        if encoding == .lexical {
            frame = [Command.getBulletin.rawValue]
        } else {
            frame = QueryPayload(
                command: Command.getBulletin.rawValue,
                data: [UInt8((lastSeenID >> 8) & 0xFF), UInt8(lastSeenID & 0xFF)]
            ).toFrame()
        }

        onQuery?("GET_BULLETIN lastID=\(lastSeenID)", "sending...", transport)
        let response = try await checkErrorResponse(try await queryOracle(payload: frame))
        onQuery?("GET_BULLETIN", "response=\(response.count)B", transport)
        return response
    }

    // MARK: - SEND MESSAGE

    public func sendMessage(_ text: String, to contact: Contact) async throws -> Int {
        guard let sess = session else { throw FFError.noSession }

        let e2eKey = try E2ECrypto.deriveKey(myPrivate: identity.privateKey, theirPublic: contact.publicKey)
        let plaintext = [UInt8](text.utf8)
        let ciphertext = try E2ECrypto.encrypt(key: e2eKey, plaintext: plaintext)

        // Recipient fingerprint = SHA256(publicKey)[0:8]
        let recipientFP = contact.fingerprintHex
        guard let fpBytes = hexToBytes(recipientFP) else { throw FFError.invalidKey }

        // Fragment CIPHERTEXT only (not fp+ciphertext).
        // Go: each fragment's Data = [recipientFP(8)] + [ciphertext_chunk]
        // The fingerprint is prepended to EVERY fragment, not just the first one.
        //
        // Per PROTOCOL.md §6.3:
        //   Proquint: max frame=20B, header=8B, fp=8B → 4 bytes ciphertext/fragment
        //   Hex:      max frame=31B per label, more capacity → 50 bytes/fragment
        let maxCiphertextPerFragment = (encoding == .proquint) ? 4 : 50
        var ctFragments = [[UInt8]]()
        for i in stride(from: 0, to: ciphertext.count, by: maxCiphertextPerFragment) {
            let end = min(i + maxCiphertextPerFragment, ciphertext.count)
            ctFragments.append(Array(ciphertext[i..<end]))
        }
        if ctFragments.isEmpty { ctFragments.append([]) }

        for (i, ctChunk) in ctFragments.enumerated() {
            try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
            let seq = sess.nextSeqNo()
            let token = sess.token(for: seq)

            // Data = [recipientFP(8)] + [ciphertext_chunk] for EVERY fragment
            // §1.2.1: frames MUST have even byte length for proquint
            var data = fpBytes  // 8 bytes fingerprint
            data.append(contentsOf: ctChunk)
            // Ensure total frame (8 header + data) is even
            if (8 + data.count) % 2 != 0 {
                data.append(0x00)
            }

            let frame = QueryPayload(
                command: Command.sendMsg.rawValue,
                seqNo: UInt8(seq & 0xFF),
                fragIndex: UInt8(i),
                fragTotal: UInt8(ctFragments.count),
                sessionToken: token,
                data: data
            ).toFrame()

            onQuery?("SEND_MSG frag=\(i+1)/\(ctFragments.count) to=\(recipientFP.prefix(8)) ct=\(ctChunk.count)B", "sending \(frame.count)B frame...", transport)
            let response = try await checkErrorResponse(try await queryOracle(payload: frame))
            onQuery?("SEND_MSG frag=\(i+1)/\(ctFragments.count)", "ACK \(response.count)B", transport)
        }
        return ctFragments.count
    }

    // MARK: - GET MESSAGES

    /// Poll for incoming messages using the Oracle's sub-protocol:
    /// Step 1: CHECK (0x00) — is there a pending message?
    /// Step 2: FETCH (0x01) × N — download 8 bytes at a time
    /// Step 3: ACK (0x02) — mark delivered
    public func pollMessages() async throws -> (data: [UInt8], senderFP: [UInt8])? {
        guard let sess = session else { throw FFError.noSession }

        // Step 1: CHECK
        try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
        let seq1 = sess.nextSeqNo()
        let token1 = sess.token(for: seq1)

        let checkFrame = QueryPayload(
            command: Command.getMsg.rawValue,
            seqNo: UInt8(seq1 & 0xFF),
            sessionToken: token1,
            data: [0x00] // CHECK sub-command
        ).toFrame()

        onQuery?("GET_MSG CHECK", "sending...", transport)
        let checkResp = try await checkErrorResponse(try await queryOracle(payload: checkFrame))

        // Response: [0x00,...] = no messages, [0x01, senderFP(4), lenHi, lenLo, 0] = has message
        guard checkResp.count >= 1 && checkResp[0] == 0x01 else {
            onQuery?("GET_MSG CHECK", "no pending messages", transport)
            return nil
        }

        let totalLen = checkResp.count >= 7 ? (Int(checkResp[5]) << 8 | Int(checkResp[6])) : 0
        onQuery?("GET_MSG CHECK", "message found, totalLen=\(totalLen)B", transport)

        // Step 2: FETCH chunks (8 bytes per response)
        var blob = [UInt8]()
        let chunksNeeded = max(1, (totalLen + 7) / 8)

        for chunkIdx in 0..<chunksNeeded {
            try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
            let seqN = sess.nextSeqNo()
            let tokenN = sess.token(for: seqN)

            let fetchFrame = QueryPayload(
                command: Command.getMsg.rawValue,
                seqNo: UInt8(seqN & 0xFF),
                sessionToken: tokenN,
                data: [0x01, UInt8(chunkIdx)] // FETCH sub-command + chunk index
            ).toFrame()

            onQuery?("GET_MSG FETCH chunk=\(chunkIdx)", "sending...", transport)
            let fetchResp = try await checkErrorResponse(try await queryOracle(payload: fetchFrame))
            blob.append(contentsOf: fetchResp)
            onQuery?("GET_MSG FETCH chunk=\(chunkIdx)", "got \(fetchResp.count)B", transport)
        }

        // Step 3: ACK
        try await Task.sleep(nanoseconds: UInt64(optimalDelay * 1_000_000_000))
        let seqAck = sess.nextSeqNo()
        let tokenAck = sess.token(for: seqAck)

        let ackFrame = QueryPayload(
            command: Command.getMsg.rawValue,
            seqNo: UInt8(seqAck & 0xFF),
            sessionToken: tokenAck,
            data: [0x02] // ACK sub-command
        ).toFrame()

        onQuery?("GET_MSG ACK", "sending...", transport)
        _ = try await checkErrorResponse(try await queryOracle(payload: ackFrame))
        onQuery?("GET_MSG ACK", "delivered", transport)

        // Trim blob to actual totalLen (Go: blob = blob[:totalLen])
        let trimmedBlob: [UInt8]
        if totalLen > 0 && blob.count > totalLen {
            trimmedBlob = Array(blob[0..<totalLen])
        } else {
            trimmedBlob = blob
        }

        // Parse blob: [senderFP(8)][ciphertext...]
        guard trimmedBlob.count > 8 else { return nil }
        let senderFP = Array(trimmedBlob[0..<8])
        let ciphertext = Array(trimmedBlob[8...])
        return (ciphertext, senderFP)
    }

    /// Decrypt received message data using sender's public key
    public func decryptMessage(_ ciphertext: [UInt8], senderPublicKey: [UInt8]) throws -> String {
        let e2eKey = try E2ECrypto.deriveKey(myPrivate: identity.privateKey, theirPublic: senderPublicKey)
        let plaintext = try E2ECrypto.decrypt(key: e2eKey, blob: ciphertext)
        guard let text = String(bytes: plaintext, encoding: .utf8) else {
            throw FFError.decryptionFailed
        }
        return text
    }

    // MARK: - DISCOVER

    public func discover() async throws {
        // §3.1: DISCOVER does NOT require a session
        let payload: [UInt8]
        if encoding == .lexical {
            payload = [Command.discover.rawValue]
        } else {
            payload = QueryPayload(command: Command.discover.rawValue).toFrame()
        }

        onQuery?("DISCOVER", "sending...", transport)
        let response = try await checkErrorResponse(try await queryOracle(payload: payload))

        if response.count >= 16 {
            let sKey = session?.keyBytes ?? [UInt8](repeating: 0, count: 32)
            domainManager.updateEpoch(encryptedSeed: Array(response.prefix(16)),
                                       sessionKey: sKey)
            onQuery?("DISCOVER", "epoch_seed updated, epoch=\(domainManager.epochNumber)", transport)
        } else {
            onQuery?("DISCOVER", "response too short (\(response.count)B)", transport)
        }
    }

    // MARK: - DNS CACHE TEST & AUTO-TUNING

    /// Optimal delay between queries (auto-tuned by cache test)
    public var optimalDelay: TimeInterval = 3.0

    /// Run Oracle's _ct cache test protocol to find the real resolver TTL
    /// Uses the Oracle's atomic counter: same counter = cached, different = fresh
    /// Tests TTLs: 0, 1, 2, 3, 5, 10 to find the sweet spot
    public func autoTuneTTL() async throws -> (optimalTTL: Int, delay: TimeInterval) {
        let domain = domainManager.activeDomain()
        let testTTLs = [0, 1, 2, 3, 5, 10]
        var results: [(ttl: Int, cached: Bool, counter1: UInt32, counter2: UInt32)] = []

        onQuery?("AUTO_TUNE", "Starting cache profiling with \(testTTLs.count) TTL values...", transport)

        for ttl in testTTLs {
            let seq = UInt16.random(in: 0...UInt16.max)
            let nonce1 = String((0..<6).map { _ in "abcdefghijklmnop".randomElement()! })
            let nonce2 = String((0..<6).map { _ in "abcdefghijklmnop".randomElement()! })

            // Query 1: _ct.<ttl>.<seq>.<nonce1>.<domain>
            let qname1 = "_ct.\(ttl).\(seq).\(nonce1).\(domain)"
            onQuery?("CACHE_TEST", "TTL=\(ttl) query 1: \(qname1)", transport)
            let ips1 = try await dnsQueryAAAA(name: qname1)
            let counter1 = extractCounter(from: ips1)

            // Wait slightly longer than the TTL we're testing
            let waitTime = max(TimeInterval(ttl) + 0.5, 1.0)
            try await Task.sleep(nanoseconds: UInt64(waitTime * 1_000_000_000))

            // Query 2: same _ct.<ttl>.<seq> but different nonce
            // If resolver cached it, counter will be same (Oracle wasn't hit)
            let qname2 = "_ct.\(ttl).\(seq).\(nonce2).\(domain)"
            onQuery?("CACHE_TEST", "TTL=\(ttl) query 2: \(qname2)", transport)
            let ips2 = try await dnsQueryAAAA(name: qname2)
            let counter2 = extractCounter(from: ips2)

            let cached = (counter1 == counter2)
            results.append((ttl: ttl, cached: cached, counter1: counter1, counter2: counter2))

            onQuery?("CACHE_TEST", "TTL=\(ttl): c1=\(counter1) c2=\(counter2) cached=\(cached)", transport)
        }

        // Find the minimum TTL where responses are NOT cached
        // That's our sweet spot — smallest TTL the resolver respects
        var bestTTL = 0
        for r in results {
            if !r.cached {
                bestTTL = r.ttl
                break
            }
        }

        // If everything is cached (aggressive resolver), use TTL=0 with longer delays
        if results.allSatisfy({ $0.cached }) {
            bestTTL = 0
            optimalDelay = 5.0  // Conservative
            onQuery?("AUTO_TUNE", "Aggressive caching detected — using 5s delay", transport)
        } else {
            // Delay = TTL + 1 second safety margin
            optimalDelay = max(TimeInterval(bestTTL) + 1.0, 2.0)
            onQuery?("AUTO_TUNE", "Optimal: TTL=\(bestTTL) delay=\(optimalDelay)s", transport)
        }

        return (bestTTL, optimalDelay)
    }

    /// Simple cache test (non-auto-tuning, just checks if resolver caches)
    public func testDNSCache() async throws -> (ttl: Int, cached: Bool) {
        let result = try await autoTuneTTL()
        return (result.optimalTTL, result.optimalTTL > 0)
    }

    /// Extract the Oracle's atomic counter from a cache test AAAA response
    /// Response format: [2001:0db8:<ttl>:<seq>:<counter_hi>:<counter_lo>:<ts_hi>:<ts_lo>]
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

    private func extractCounter(from ips: [[UInt8]]) -> UInt32 {
        guard let ip = ips.first, ip.count >= 12 else { return 0 }
        return UInt32(ip[8]) << 24 | UInt32(ip[9]) << 16 | UInt32(ip[10]) << 8 | UInt32(ip[11])
    }

    // MARK: - Transport

    /// Encoding mode for DNS queries
    public enum QueryEncoding: String {
        case proquint  // Primary — censored networks (CVCVC words)
        case hex       // Simple — uncensored networks
        case lexical   // Legacy — compact commands only
    }

    /// Active encoding mode (default: proquint per protocol §1.2.1)
    public var encoding: QueryEncoding = .proquint

    private var transport: String {
        useRelay ? "HTTP" : "DNS(\(encoding.rawValue))"
    }

    private func queryOracle(payload: [UInt8]) async throws -> [UInt8] {
        if useRelay {
            return try await queryViaHTTP(payload: payload)
        } else {
            return try await queryViaDNS(payload: payload)
        }
    }

    /// DNS AAAA transport — encodes frame as DNS query per PROTOCOL.md
    ///
    /// Encoding priority (§1.2):
    ///   1. Proquint (primary): CVCVC words, 20 bytes/label, evades entropy detectors
    ///   2. Hex: hex-encoded labels, 31 bytes/label, for uncensored networks
    ///   3. Lexical: word-list steganography, for 1-2 byte compact commands only
    ///
    /// Every query includes a unique q-<random> subdomain for cache isolation (§1.3)
    private func queryViaDNS(payload: [UInt8]) async throws -> [UInt8] {
        let domain = domainManager.activeDomain()

        // Generate per-query cache-busting nonce (§1.3)
        let nonce = (0..<8).map { _ in String(format: "%x", UInt8.random(in: 0...15)) }.joined()
        let nonceLabel = "q-\(nonce)"

        let frameLabels: String

        switch encoding {
        case .proquint:
            // §1.2.1: Proquint encoding — all frames use this on censored networks
            // Frames MUST have even byte length (pad if odd)
            var frame = payload
            if frame.count % 2 != 0 {
                frame.append(0x00)
            }
            // Single label if ≤20 bytes, multi-label if larger
            if frame.count <= Proquint.maxBytesPerLabel {
                frameLabels = Proquint.encode(frame)
            } else {
                // Split across multiple proquint labels
                var labels = [String]()
                for i in stride(from: 0, to: frame.count, by: Proquint.maxBytesPerLabel) {
                    let end = min(i + Proquint.maxBytesPerLabel, frame.count)
                    var chunk = Array(frame[i..<end])
                    if chunk.count % 2 != 0 { chunk.append(0x00) }
                    labels.append(Proquint.encode(chunk))
                }
                frameLabels = labels.joined(separator: ".")
            }

        case .hex:
            // §1.2.2: Hex encoding — frame bytes as hex labels
            let hexStr = payload.map { String(format: "%02x", $0) }.joined()
            // Max 62 hex chars per label (31 bytes)
            var labels = [String]()
            var i = hexStr.startIndex
            while i < hexStr.endIndex {
                let end = hexStr.index(i, offsetBy: 62, limitedBy: hexStr.endIndex) ?? hexStr.endIndex
                labels.append(String(hexStr[i..<end]))
                i = end
            }
            frameLabels = labels.joined(separator: ".")

        case .lexical:
            // §1.2.3: Lexical — only for 1-2 byte compact payloads
            let label = try LexicalEncoder.encode(payload: payload, profile: profile)
            frameLabels = label
        }

        // Assemble: <frame_labels>.q-<nonce>.<domain>
        let queryName = "\(frameLabels).\(nonceLabel).\(domain)"

        onQuery?("DNS_QUERY [\(encoding.rawValue)]", queryName, transport)
        let ips = try await dnsQueryAAAA(name: queryName)
        let (responsePayload, _, _) = try AAAAEncoder.decode(ips)
        await rateLimiter.record(success: true)
        return responsePayload
    }

    /// HTTP Relay transport (supports both HTTPS and insecure HTTP)
    private func queryViaHTTP(payload: [UInt8]) async throws -> [UInt8] {
        guard !relayURL.isEmpty else { throw FFError.helloFailed("Relay URL not configured") }

        let url = URL(string: relayURL + "/api/query")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        if !relayAPIKey.isEmpty {
            request.setValue(relayAPIKey, forHTTPHeaderField: "X-API-Key")
        }
        request.httpBody = Data(payload)
        request.timeoutInterval = 15

        let session: URLSession
        if relayAllowInsecure {
            let config = URLSessionConfiguration.default
            session = URLSession(configuration: config, delegate: InsecureDelegate.shared, delegateQueue: nil)
        } else {
            session = URLSession.shared
        }

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw FFError.helloFailed("HTTP relay returned status \(code)")
        }
        await rateLimiter.record(success: true)
        return [UInt8](data)
    }

    /// Raw DNS AAAA query via UDP
    private func dnsQueryAAAA(name: String) async throws -> [[UInt8]] {
        let query = DNSPacket.buildQuery(name: name, type: .AAAA)

        return try await withCheckedThrowingContinuation { continuation in
            var resumed = false
            let lock = NSLock()

            func safeResume(_ result: Result<[[UInt8]], Error>) {
                lock.lock()
                defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                continuation.resume(with: result)
            }

            let connection = NWConnection(
                host: NWEndpoint.Host(resolver),
                port: NWEndpoint.Port(integerLiteral: 53),
                using: .udp
            )

            connection.stateUpdateHandler = { state in
                if case .failed(let err) = state {
                    safeResume(.failure(err))
                }
            }

            connection.start(queue: .global())

            connection.send(content: Data(query), completion: .contentProcessed { error in
                if let error = error {
                    safeResume(.failure(error))
                    return
                }

                connection.receive(minimumIncompleteLength: 12, maximumLength: 4096) { data, _, _, error in
                    connection.cancel()
                    if let error = error {
                        safeResume(.failure(error))
                        return
                    }
                    guard let data = data else {
                        safeResume(.failure(FFError.noRecords))
                        return
                    }
                    do {
                        let ips = try DNSPacket.parseAAAAResponse([UInt8](data))
                        safeResume(.success(ips))
                    } catch {
                        safeResume(.failure(error))
                    }
                }
            })

            DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
                connection.cancel()
                safeResume(.failure(FFError.timeout))
            }
        }
    }
}

// MARK: - DNS Packet Builder/Parser

enum DNSRecordType: UInt16 {
    case AAAA = 28
}

enum DNSPacket {
    static func buildQuery(name: String, type: DNSRecordType) -> [UInt8] {
        var packet = [UInt8]()
        let txid = UInt16.random(in: 0...UInt16.max)
        packet.append(UInt8((txid >> 8) & 0xFF))
        packet.append(UInt8(txid & 0xFF))
        packet.append(0x01); packet.append(0x00) // Flags: recursion desired
        packet.append(0x00); packet.append(0x01) // Questions: 1
        packet.append(contentsOf: [0,0, 0,0, 0,0]) // Answer, Auth, Additional: 0

        for label in name.split(separator: ".") {
            let bytes = [UInt8](label.utf8)
            packet.append(UInt8(bytes.count))
            packet.append(contentsOf: bytes)
        }
        packet.append(0)

        packet.append(UInt8((type.rawValue >> 8) & 0xFF))
        packet.append(UInt8(type.rawValue & 0xFF))
        packet.append(0x00); packet.append(0x01) // IN class

        return packet
    }

    static func parseAAAAResponse(_ data: [UInt8]) throws -> [[UInt8]] {
        guard data.count >= 12 else { throw FFError.noRecords }

        let anCount = UInt16(data[6]) << 8 | UInt16(data[7])
        guard anCount > 0 else { throw FFError.noRecords }

        var pos = 12
        // Skip QNAME
        while pos < data.count {
            let len = Int(data[pos])
            if len == 0 { pos += 1; break }
            if len & 0xC0 == 0xC0 { pos += 2; break }
            pos += 1 + len
        }
        pos += 4 // QTYPE + QCLASS

        var records = [[UInt8]]()
        for _ in 0..<anCount {
            guard pos + 12 <= data.count else { break }
            if data[pos] & 0xC0 == 0xC0 { pos += 2 }
            else { while pos < data.count && data[pos] != 0 { pos += Int(data[pos]) + 1 }; pos += 1 }

            let rtype = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
            pos += 2 + 2 + 4 // TYPE + CLASS + TTL
            let rdLength = Int(UInt16(data[pos]) << 8 | UInt16(data[pos+1]))
            pos += 2

            if rtype == DNSRecordType.AAAA.rawValue && rdLength == 16 {
                guard pos + 16 <= data.count else { break }
                records.append(Array(data[pos..<(pos+16)]))
            }
            pos += rdLength
        }
        return records
    }
}

/// Allows insecure HTTP and self-signed HTTPS connections for relay transport
private class InsecureDelegate: NSObject, URLSessionDelegate {
    static let shared = InsecureDelegate()
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
