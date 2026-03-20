import Foundation
import CryptoKit

/// Ed25519 bulletin signature verification
public enum BulletinVerifier {

    /// Verify a signed bulletin from the Oracle
    /// Message format: [bulletinID(2)] + [timestamp(4)] + [SHA256(content)]
    public static func verify(
        publicKey: [UInt8], bulletinID: UInt16, timestamp: UInt32,
        content: [UInt8], signature: [UInt8]
    ) -> Bool {
        var message = [UInt8]()
        message.append(UInt8((bulletinID >> 8) & 0xFF))
        message.append(UInt8(bulletinID & 0xFF))
        message.append(UInt8((timestamp >> 24) & 0xFF))
        message.append(UInt8((timestamp >> 16) & 0xFF))
        message.append(UInt8((timestamp >> 8) & 0xFF))
        message.append(UInt8(timestamp & 0xFF))
        let hash = SHA256.hash(data: content)
        message.append(contentsOf: hash)

        return SigningKeyPair.verify(signature: signature, data: message, publicKey: publicKey)
    }
}
