import Foundation
import CryptoKit

/// User identity — X25519 keypair + fingerprint
public struct Identity: Codable {
    public let displayName: String
    public let publicKey: [UInt8]    // 32 bytes
    public let privateKey: [UInt8]   // 32 bytes
    public let fingerprint: [UInt8]  // 8 bytes = SHA256(publicKey)[0:8]

    public var fingerprintHex: String {
        fingerprint.map { String(format: "%02x", $0) }.joined()
    }

    public static func generate(displayName: String) -> Identity {
        let kp = KeyPair()
        let hash = SHA256.hash(data: kp.publicKeyBytes)
        return Identity(
            displayName: displayName,
            publicKey: kp.publicKeyBytes,
            privateKey: kp.privateKeyBytes,
            fingerprint: Array(hash.prefix(8))
        )
    }

    /// Save to Keychain-backed file
    public func save(to url: URL) throws {
        let data = try JSONEncoder().encode(self)
        try data.write(to: url, options: .completeFileProtection)
    }

    public static func load(from url: URL) throws -> Identity {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Identity.self, from: data)
    }
}

/// A known contact
public struct Contact: Codable, Identifiable {
    public var id: String { fingerprintHex }
    public let displayName: String
    public let publicKey: [UInt8]    // 32 bytes
    public let fingerprintHex: String

    public init(displayName: String, publicKeyHex: String) throws {
        guard let bytes = Self.hexToBytes(publicKeyHex), bytes.count == 32 else {
            throw FFError.invalidKey
        }
        self.displayName = displayName
        self.publicKey = bytes
        let hash = SHA256.hash(data: bytes)
        self.fingerprintHex = Array(hash.prefix(8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func hexToBytes(_ hex: String) -> [UInt8]? {
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            guard let next = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) else { return nil }
            guard let byte = UInt8(hex[i..<next], radix: 16) else { return nil }
            bytes.append(byte)
            i = next
        }
        return bytes
    }
}

/// Contact book manager
public class ContactBook: ObservableObject {
    @Published public var contacts: [Contact] = []

    private let storageURL: URL

    public init(storageURL: URL) {
        self.storageURL = storageURL
        load()
    }

    public func add(_ contact: Contact) {
        contacts.removeAll { $0.fingerprintHex == contact.fingerprintHex }
        contacts.append(contact)
        save()
    }

    public func find(byName name: String) -> Contact? {
        contacts.first { $0.displayName.lowercased() == name.lowercased() }
    }

    public func find(byFingerprint fp: String) -> Contact? {
        contacts.first { $0.fingerprintHex.hasPrefix(fp.lowercased()) }
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(contacts) else { return }
        try? data.write(to: storageURL)
    }

    private func load() {
        guard let data = try? Data(contentsOf: storageURL),
              let loaded = try? JSONDecoder().decode([Contact].self, from: data) else { return }
        contacts = loaded
    }
}
