import Foundation

/// Wire format: [cmd(1)][seqNo(1)][fragIdx(1)][fragTotal(1)][token(4)][data(N)]
public struct QueryPayload {
    public static let headerSize = 8

    public var command: UInt8
    public var seqNo: UInt8
    public var fragIndex: UInt8
    public var fragTotal: UInt8
    public var sessionToken: [UInt8]  // 4 bytes
    public var data: [UInt8]

    public init(command: UInt8, seqNo: UInt8 = 0, fragIndex: UInt8 = 0,
                fragTotal: UInt8 = 1, sessionToken: [UInt8] = [0,0,0,0],
                data: [UInt8] = []) {
        self.command = command
        self.seqNo = seqNo
        self.fragIndex = fragIndex
        self.fragTotal = fragTotal
        self.sessionToken = sessionToken.count >= 4 ? Array(sessionToken[0..<4]) : sessionToken + [UInt8](repeating: 0, count: 4 - sessionToken.count)
        self.data = data
    }

    /// Serialize to wire format
    public func toFrame() -> [UInt8] {
        var frame = [UInt8]()
        frame.reserveCapacity(Self.headerSize + data.count)
        frame.append(command)
        frame.append(seqNo)
        frame.append(fragIndex)
        frame.append(fragTotal)
        frame.append(contentsOf: sessionToken)
        frame.append(contentsOf: data)
        return frame
    }

    /// Parse from wire format
    public static func parse(_ frame: [UInt8]) throws -> QueryPayload {
        guard frame.count >= headerSize else {
            throw FFError.frameTooShort(frame.count)
        }
        return QueryPayload(
            command: frame[0],
            seqNo: frame[1],
            fragIndex: frame[2],
            fragTotal: frame[3],
            sessionToken: Array(frame[4..<8]),
            data: frame.count > headerSize ? Array(frame[headerSize...]) : []
        )
    }
}

public enum FFError: Error, LocalizedError {
    case frameTooShort(Int)
    case noRecords
    case recordTooShort
    case payloadTooLarge
    case noTemplateMatched
    case wrongDomain
    case noSession
    case helloFailed(String)
    case decryptionFailed
    case invalidKey
    case budgetExhausted
    case timeout

    public var errorDescription: String? {
        switch self {
        case .frameTooShort(let n): return "Frame too short: \(n) bytes"
        case .noRecords: return "No AAAA records in response"
        case .payloadTooLarge: return "Payload too large for template"
        case .noSession: return "No active session"
        case .helloFailed(let msg): return "HELLO failed: \(msg)"
        case .budgetExhausted: return "Daily query budget exhausted"
        default: return String(describing: self)
        }
    }
}
