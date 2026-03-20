import Foundation
import Network
import CryptoKit

/// Main FreeFlow client connection — handles all protocol operations over DNS
public class FFConnection: ObservableObject {
    @Published public var state: ConnectionState = .disconnected
    @Published public var session: FFSession?

    public let identity: Identity
    public let domainManager: DomainManager
    public let rateLimiter = AdaptiveRateLimiter()
    public var profile: LexicalProfile
    public var oraclePublicKey: [UInt8]  // Compiled-in X25519 pubkey

    private var resolver: String = "8.8.8.8"
    private var seqNo: UInt32 = 0

    public enum ConnectionState {
        case disconnected, connecting, connected, dormant
    }

    public init(identity: Identity, oraclePublicKey: [UInt8], seed: [UInt8], profile: LexicalProfile) {
        self.identity = identity
        self.oraclePublicKey = oraclePublicKey
        self.domainManager = DomainManager(seed: seed)
        self.profile = profile
    }

    // MARK: - PING

    /// Ping Oracle, get server time for clock sync
    public func ping() async throws -> Date {
        let payload: [UInt8] = [Command.ping.rawValue]
        let response = try await queryOracle(payload: payload)
        guard response.count >= 4 else { throw FFError.frameTooShort(response.count) }
        let serverTime = UInt32(response[0]) << 24 | UInt32(response[1]) << 16 |
                         UInt32(response[2]) << 8 | UInt32(response[3])
        let date = Date(timeIntervalSince1970: TimeInterval(serverTime))
        domainManager.syncClock(serverTime: serverTime)
        return date
    }

    // MARK: - HELLO (Session Establishment)

    /// Establish encrypted session with Oracle via 4-query HELLO handshake
    public func connect() async throws {
        state = .connecting
        let ephemeral = KeyPair()
        let pubBytes = ephemeral.publicKeyBytes
        let helloNonce = UInt16.random(in: 0..<65536)

        // Send 4 chunks of public key
        for i in 0..<4 {
            let chunk = Array(pubBytes[(i*8)..<((i+1)*8)])
            var payload: [UInt8] = [Command.hello.rawValue, UInt8(i), 4]
            payload.append(UInt8((helloNonce >> 8) & 0xFF))
            payload.append(UInt8(helloNonce & 0xFF))
            payload.append(contentsOf: chunk)

            let response = try await queryOracle(payload: payload)

            if i == 3 {
                // Final response contains encrypted session info
                let sharedSecret = try ephemeral.sharedSecret(with: oraclePublicKey)
                let sessionKeyBytes = FFSession.deriveKey(sharedSecret: sharedSecret)
                let sessionID = try FFSession.decodeHelloComplete(
                    response: response, sessionKey: sessionKeyBytes)

                session = FFSession(id: sessionID, keyBytes: sessionKeyBytes)
                state = .connected
            }
            // Rate limit between HELLO queries
            if i < 3 { try await rateLimiter.waitForNext() }
        }
    }

    // MARK: - GET BULLETIN

    /// Fetch signed bulletin (no session needed)
    public func getBulletin(lastSeenID: UInt16 = 0) async throws -> [UInt8] {
        var payload: [UInt8] = [Command.getBulletin.rawValue]
        payload.append(UInt8((lastSeenID >> 8) & 0xFF))
        payload.append(UInt8(lastSeenID & 0xFF))
        return try await queryOracle(payload: payload)
    }

    // MARK: - SEND MESSAGE

    /// Send an encrypted message to a contact
    public func sendMessage(_ text: String, to contact: Contact) async throws {
        guard let sess = session else { throw FFError.noSession }

        // E2E encrypt
        let e2eKey = try E2ECrypto.deriveKey(myPrivate: identity.privateKey, theirPublic: contact.publicKey)
        let plaintext = [UInt8](text.utf8)
        let ciphertext = try E2ECrypto.encrypt(key: e2eKey, plaintext: plaintext)

        // Fragment into chunks (6 bytes per query payload after header)
        let chunkSize = 6
        let fragments = stride(from: 0, to: ciphertext.count, by: chunkSize).map {
            Array(ciphertext[$0..<min($0 + chunkSize, ciphertext.count)])
        }

        for (i, fragment) in fragments.enumerated() {
            try await rateLimiter.waitForNext()
            let seq = sess.nextSeqNo()
            let token = sess.token(for: seq)

            var payload: [UInt8] = [Command.sendMsg.rawValue]
            payload.append(UInt8(i))
            payload.append(UInt8(fragments.count))
            payload.append(contentsOf: token)
            // Recipient fingerprint (first 8 bytes)
            payload.append(contentsOf: Array(contact.publicKey.prefix(8)))
            payload.append(contentsOf: fragment)

            _ = try await queryOracle(payload: payload)
        }
    }

    // MARK: - GET MESSAGES

    /// Poll for incoming messages
    public func pollMessages() async throws -> [UInt8]? {
        guard let sess = session else { throw FFError.noSession }

        try await rateLimiter.waitForNext()
        let seq = sess.nextSeqNo()
        let token = sess.token(for: seq)

        var payload: [UInt8] = [Command.getMsg.rawValue]
        payload.append(contentsOf: token)
        payload.append(0) // lastMsgID

        let response = try await queryOracle(payload: payload)
        if response.count <= 1 { return nil } // No messages
        return response
    }

    // MARK: - DISCOVER

    /// Request new domain table + epoch seed
    public func discover() async throws {
        guard let sess = session else { throw FFError.noSession }
        let seq = sess.nextSeqNo()
        let token = sess.token(for: seq)

        var payload: [UInt8] = [Command.discover.rawValue]
        payload.append(contentsOf: token)

        let response = try await queryOracle(payload: payload)
        // Response contains encrypted epoch seed
        if response.count >= 16 {
            domainManager.updateEpoch(encryptedSeed: Array(response.prefix(16)),
                                       sessionKey: sess.keyBytes)
        }
    }

    // MARK: - DNS Query Engine

    /// Issue a single AAAA query and decode the response
    private func queryOracle(payload: [UInt8]) async throws -> [UInt8] {
        let domain = domainManager.activeDomain()
        let queryName = try LexicalEncoder.encodeQuery(
            payload: payload, domain: domain, profile: profile)

        let ips = try await dnsQueryAAAA(name: queryName)
        let (responsePayload, _, _) = try AAAAEncoder.decode(ips)
        return responsePayload
    }

    /// Raw DNS AAAA query via UDP
    private func dnsQueryAAAA(name: String) async throws -> [[UInt8]] {
        // Build DNS query packet
        let query = DNSPacket.buildQuery(name: name, type: .AAAA)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NWConnection(
                host: NWEndpoint.Host(resolver),
                port: NWEndpoint.Port(integerLiteral: 53),
                using: .udp
            )

            connection.stateUpdateHandler = { state in
                if case .failed(let err) = state {
                    continuation.resume(throwing: err)
                }
            }

            connection.start(queue: .global())

            connection.send(content: Data(query), completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: error)
                    return
                }

                connection.receive(minimumIncompleteLength: 12, maximumLength: 4096) { data, _, _, error in
                    connection.cancel()
                    if let error = error {
                        continuation.resume(throwing: error)
                        return
                    }
                    guard let data = data else {
                        continuation.resume(throwing: FFError.noRecords)
                        return
                    }
                    do {
                        let ips = try DNSPacket.parseAAAAResponse([UInt8](data))
                        continuation.resume(returning: ips)
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            })

            // Timeout
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
                connection.cancel()
            }
        }
    }
}

// MARK: - DNS Packet Builder/Parser

enum DNSRecordType: UInt16 {
    case AAAA = 28
}

enum DNSPacket {
    /// Build a DNS AAAA query packet
    static func buildQuery(name: String, type: DNSRecordType) -> [UInt8] {
        var packet = [UInt8]()
        // Transaction ID
        let txid = UInt16.random(in: 0..<65536)
        packet.append(UInt8((txid >> 8) & 0xFF))
        packet.append(UInt8(txid & 0xFF))
        // Flags: standard query, recursion desired
        packet.append(0x01); packet.append(0x00)
        // Questions: 1
        packet.append(0x00); packet.append(0x01)
        // Answer, Authority, Additional: 0
        packet.append(contentsOf: [0,0, 0,0, 0,0])

        // QNAME: encode domain name
        for label in name.split(separator: ".") {
            let bytes = [UInt8](label.utf8)
            packet.append(UInt8(bytes.count))
            packet.append(contentsOf: bytes)
        }
        packet.append(0) // Root label

        // QTYPE: AAAA (28)
        packet.append(UInt8((type.rawValue >> 8) & 0xFF))
        packet.append(UInt8(type.rawValue & 0xFF))
        // QCLASS: IN (1)
        packet.append(0x00); packet.append(0x01)

        return packet
    }

    /// Parse AAAA records from DNS response
    static func parseAAAAResponse(_ data: [UInt8]) throws -> [[UInt8]] {
        guard data.count >= 12 else { throw FFError.noRecords }

        let anCount = UInt16(data[6]) << 8 | UInt16(data[7])
        guard anCount > 0 else { throw FFError.noRecords }

        // Skip header (12 bytes) + question section
        var pos = 12
        // Skip QNAME
        while pos < data.count {
            let len = Int(data[pos])
            if len == 0 { pos += 1; break }
            if len & 0xC0 == 0xC0 { pos += 2; break } // Pointer
            pos += 1 + len
        }
        // Skip QTYPE + QCLASS
        pos += 4

        var records = [[UInt8]]()
        for _ in 0..<anCount {
            guard pos + 12 <= data.count else { break }
            // Skip NAME (may be pointer)
            if data[pos] & 0xC0 == 0xC0 { pos += 2 }
            else { while pos < data.count && data[pos] != 0 { pos += Int(data[pos]) + 1 }; pos += 1 }

            // TYPE, CLASS, TTL
            let rtype = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
            pos += 2 // TYPE
            pos += 2 // CLASS
            pos += 4 // TTL
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
