import Foundation
import CryptoKit

/// End-to-end encryption between users using X25519 + ChaCha20-Poly1305
public enum E2ECrypto {

    /// Derive E2E key from my private key + their public key
    public static func deriveKey(myPrivate: [UInt8], theirPublic: [UInt8]) throws -> [UInt8] {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivate)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublic)
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        let derived = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            info: Data("freeflow-e2e-v1".utf8),
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Array($0) }
    }

    /// Encrypt plaintext → [nonce(12)] + [ciphertext] + [tag(16)]
    public static func encrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let symKey = SymmetricKey(data: key)
        let nonce = ChaChaPoly.Nonce()
        let sealed = try ChaChaPoly.seal(Data(plaintext), using: symKey, nonce: nonce)
        var result = [UInt8]()
        result.append(contentsOf: sealed.nonce.withUnsafeBytes { Array($0) })
        result.append(contentsOf: sealed.ciphertext)
        result.append(contentsOf: sealed.tag)
        return result
    }

    /// Decrypt blob → plaintext
    public static func decrypt(key: [UInt8], blob: [UInt8]) throws -> [UInt8] {
        guard blob.count >= 28 else { throw FFError.decryptionFailed }
        let symKey = SymmetricKey(data: key)
        let nonce = try ChaChaPoly.Nonce(data: Data(blob[0..<12]))
        let ct = blob[12..<(blob.count - 16)]
        let tag = blob[(blob.count - 16)...]
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return [UInt8](try ChaChaPoly.open(box, using: symKey))
    }
}
