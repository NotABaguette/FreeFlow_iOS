import XCTest
@testable import FreeFlowCore

final class FrameTests: XCTestCase {
    func testBuildAndParseFrame() throws {
        let payload = QueryPayload(
            command: Command.ping.rawValue,
            seqNo: 42,
            fragIndex: 0,
            fragTotal: 1,
            data: [0xDE, 0xAD]
        )
        let frame = payload.toFrame()
        XCTAssertEqual(frame.count, 10) // 8 header + 2 data

        let parsed = try QueryPayload.parse(frame)
        XCTAssertEqual(parsed.command, Command.ping.rawValue)
        XCTAssertEqual(parsed.seqNo, 42)
        XCTAssertEqual(parsed.fragIndex, 0)
        XCTAssertEqual(parsed.fragTotal, 1)
        XCTAssertEqual(parsed.data, [0xDE, 0xAD])
    }

    func testFrameTooShort() {
        XCTAssertThrowsError(try QueryPayload.parse([0x01, 0x02]))
    }
}

final class AAAATests: XCTestCase {
    func testEncodeDecodeRoundTrip() throws {
        let payload: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let records = AAAAEncoder.encode(
            payload: payload, seqNo: 5, fragIdx: 0, fragTotal: 1, isLast: true
        )
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].count, 16)

        let (decoded, seqNo, isLast) = try AAAAEncoder.decode(records)
        XCTAssertEqual(seqNo, 5)
        XCTAssertTrue(isLast)
        XCTAssertEqual(Array(decoded.prefix(8)), payload)
    }

    func testMultiRecordPayload() throws {
        let payload: [UInt8] = Array(repeating: 0xAB, count: 20)
        let records = AAAAEncoder.encode(
            payload: payload, seqNo: 1, fragIdx: 0, fragTotal: 1, isLast: true
        )
        XCTAssertEqual(records.count, 3) // ceil(20/8)

        let (decoded, _, _) = try AAAAEncoder.decode(records)
        XCTAssertEqual(Array(decoded.prefix(20)), payload)
    }
}

final class CryptoTests: XCTestCase {
    func testKeyPairGeneration() {
        let kp = KeyPair()
        XCTAssertEqual(kp.publicKeyBytes.count, 32)
        XCTAssertEqual(kp.privateKeyBytes.count, 32)
    }

    func testECDH() throws {
        let alice = KeyPair()
        let bob = KeyPair()
        let secretA = try alice.sharedSecret(with: bob.publicKeyBytes)
        let secretB = try bob.sharedSecret(with: alice.publicKeyBytes)
        // Both should derive the same session key
        let keyA = FFSession.deriveKey(sharedSecret: secretA)
        let keyB = FFSession.deriveKey(sharedSecret: secretB)
        XCTAssertEqual(keyA, keyB)
    }

    func testSessionEncryptDecrypt() throws {
        let kp1 = KeyPair()
        let kp2 = KeyPair()
        let shared = try kp1.sharedSecret(with: kp2.publicKeyBytes)
        let keyBytes = FFSession.deriveKey(sharedSecret: shared)
        let session = FFSession(id: [1,2,3,4,5,6,7,8], keyBytes: keyBytes)

        let plaintext: [UInt8] = Array("Hello FreeFlow!".utf8)
        let encrypted = try session.encrypt(plaintext)
        let decrypted = try session.decrypt(encrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testSessionTokenRotation() {
        let session = FFSession(id: [1,2,3,4,5,6,7,8],
                                keyBytes: Array(repeating: 0x42, count: 32))
        let t1 = session.token(for: 1)
        let t2 = session.token(for: 2)
        let t3 = session.token(for: 1)
        XCTAssertEqual(t1.count, 4)
        XCTAssertNotEqual(t1, t2) // Different seq → different token
        XCTAssertEqual(t1, t3)    // Same seq → same token
    }
}

final class E2ETests: XCTestCase {
    func testE2EEncryptDecrypt() throws {
        let alice = KeyPair()
        let bob = KeyPair()

        let keyAB = try E2ECrypto.deriveKey(myPrivate: alice.privateKeyBytes,
                                             theirPublic: bob.publicKeyBytes)
        let keyBA = try E2ECrypto.deriveKey(myPrivate: bob.privateKeyBytes,
                                             theirPublic: alice.publicKeyBytes)
        XCTAssertEqual(keyAB, keyBA)

        let plaintext: [UInt8] = Array("Secret message".utf8)
        let encrypted = try E2ECrypto.encrypt(key: keyAB, plaintext: plaintext)
        let decrypted = try E2ECrypto.decrypt(key: keyBA, blob: encrypted)
        XCTAssertEqual(decrypted, plaintext)
    }
}

final class IdentityTests: XCTestCase {
    func testIdentityGeneration() {
        let id = Identity.generate(displayName: "Alice")
        XCTAssertEqual(id.publicKey.count, 32)
        XCTAssertEqual(id.privateKey.count, 32)
        XCTAssertEqual(id.fingerprint.count, 8)
        XCTAssertEqual(id.fingerprintHex.count, 16)
    }
}

final class CommandTests: XCTestCase {
    func testNeedsSession() {
        XCTAssertFalse(Command.ping.needsSession)
        XCTAssertFalse(Command.hello.needsSession)
        XCTAssertFalse(Command.getBulletin.needsSession)
        XCTAssertTrue(Command.sendMsg.needsSession)
        XCTAssertTrue(Command.getMsg.needsSession)
        XCTAssertTrue(Command.ack.needsSession)
    }
}
