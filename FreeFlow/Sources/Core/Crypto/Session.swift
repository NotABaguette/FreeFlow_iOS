import Foundation
import CryptoKit

/// Active session with the Oracle
public class FFSession {
    public let id: [UInt8]           // 8 bytes
    public let key: SymmetricKey     // 32 bytes (ChaCha20-Poly1305)
    public let keyBytes: [UInt8]
    public let createdAt: Date
    public var lastActive: Date
    public var lastSeqNo: UInt32 = 0

    public init(id: [UInt8], keyBytes: [UInt8]) {
        self.id = id
        self.keyBytes = keyBytes
        self.key = SymmetricKey(data: keyBytes)
        self.createdAt = Date()
        self.lastActive = Date()
    }

    public func nextSeqNo() -> UInt32 {
        lastSeqNo += 1
        lastActive = Date()
        return lastSeqNo
    }

    /// Compute rotating session token for a given sequence number
    public func token(for seqNo: UInt32) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: 4)
        buf[0] = UInt8((seqNo >> 24) & 0xFF)
        buf[1] = UInt8((seqNo >> 16) & 0xFF)
        buf[2] = UInt8((seqNo >> 8) & 0xFF)
        buf[3] = UInt8(seqNo & 0xFF)
        let mac = HMAC<SHA256>.authenticationCode(for: buf, using: key)
        return Array(mac.prefix(4))
    }

    /// Encrypt plaintext with session key (ChaCha20-Poly1305 via ChaChaPoly)
    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        let nonce = ChaChaPoly.Nonce()
        let sealed = try ChaChaPoly.seal(Data(plaintext), using: key, nonce: nonce)
        // [nonce(12)] + [ciphertext] + [tag(16)]
        var result = [UInt8]()
        result.append(contentsOf: sealed.nonce.withUnsafeBytes { Array($0) })
        result.append(contentsOf: sealed.ciphertext)
        result.append(contentsOf: sealed.tag)
        return result
    }

    /// Decrypt ciphertext with session key
    public func decrypt(_ blob: [UInt8]) throws -> [UInt8] {
        guard blob.count >= 28 else { throw FFError.decryptionFailed } // 12 nonce + 16 tag minimum
        let nonce = try ChaChaPoly.Nonce(data: Data(blob[0..<12]))
        let ct = blob[12..<(blob.count - 16)]
        let tag = blob[(blob.count - 16)...]
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        let plaintext = try ChaChaPoly.open(box, using: key)
        return [UInt8](plaintext)
    }

    /// Derive session key from ECDH shared secret
    public static func deriveKey(sharedSecret: SharedSecret) -> [UInt8] {
        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            info: Data("freeflow-v2-session".utf8),
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Array($0) }
    }

    /// Compute HELLO mask for session ID decryption
    public static func helloMask(sessionKey: [UInt8]) -> [UInt8] {
        let key = SymmetricKey(data: sessionKey)
        let mac = HMAC<SHA256>.authenticationCode(for: Data("freeflow-hello-complete".utf8), using: key)
        return Array(mac.prefix(8))
    }

    /// Decode HELLO_COMPLETE response to extract session ID
    public static func decodeHelloComplete(response: [UInt8], sessionKey: [UInt8]) throws -> [UInt8] {
        guard response.count >= 8 else { throw FFError.helloFailed("response too short") }
        let mask = helloMask(sessionKey: sessionKey)
        var sessionID = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 {
            sessionID[i] = response[i] ^ mask[i]
        }
        return sessionID
    }
}
