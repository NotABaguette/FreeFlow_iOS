import Foundation
import CryptoKit

/// X25519 and Ed25519 key generation and management
public struct KeyPair {
    public let privateKey: Curve25519.KeyAgreement.PrivateKey
    public let publicKey: Curve25519.KeyAgreement.PublicKey

    public var publicKeyBytes: [UInt8] { [UInt8](publicKey.rawRepresentation) }
    public var privateKeyBytes: [UInt8] { [UInt8](privateKey.rawRepresentation) }

    public init() {
        self.privateKey = Curve25519.KeyAgreement.PrivateKey()
        self.publicKey = privateKey.publicKey
    }

    public init(privateKeyBytes: [UInt8]) throws {
        self.privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyBytes)
        self.publicKey = self.privateKey.publicKey
    }

    /// ECDH shared secret with another party's public key
    public func sharedSecret(with otherPublic: [UInt8]) throws -> SharedSecret {
        let otherKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: otherPublic)
        return try privateKey.sharedSecretFromKeyAgreement(with: otherKey)
    }
}

/// Ed25519 signing key pair
public struct SigningKeyPair {
    public let privateKey: Curve25519.Signing.PrivateKey
    public let publicKey: Curve25519.Signing.PublicKey

    public var publicKeyBytes: [UInt8] { [UInt8](publicKey.rawRepresentation) }

    public init() {
        self.privateKey = Curve25519.Signing.PrivateKey()
        self.publicKey = privateKey.publicKey
    }

    public init(publicKeyBytes: [UInt8]) throws {
        self.publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
        self.privateKey = Curve25519.Signing.PrivateKey() // placeholder, can't reconstruct
    }

    public func sign(_ data: [UInt8]) throws -> [UInt8] {
        let sig = try privateKey.signature(for: Data(data))
        return [UInt8](sig)
    }

    public static func verify(signature: [UInt8], data: [UInt8], publicKey: [UInt8]) -> Bool {
        guard let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pubKey.isValidSignature(Data(signature), for: Data(data))
    }
}
