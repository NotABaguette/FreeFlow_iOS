import Foundation

/// IPv6 prefix bytes for realistic CDN masquerading
public struct IPv6Prefix {
    public let bytes: [UInt8]  // 4 bytes
    public let name: String

    public static let all: [IPv6Prefix] = [
        IPv6Prefix(bytes: [0x26, 0x06, 0x47, 0x00], name: "cloudflare"),
        IPv6Prefix(bytes: [0x26, 0x07, 0xf8, 0xb0], name: "google"),
        IPv6Prefix(bytes: [0x26, 0x00, 0x1f, 0x18], name: "aws"),
        IPv6Prefix(bytes: [0x2a, 0x00, 0x14, 0x50], name: "google-eu"),
        IPv6Prefix(bytes: [0x24, 0x00, 0xcb, 0x00], name: "cloudflare-apac"),
    ]

    public static func random() -> IPv6Prefix {
        all.randomElement()!
    }
}

/// Encodes/decodes data into AAAA (IPv6) DNS responses
///
/// Layout per 16-byte IPv6 address:
///   [0-3]  CDN prefix
///   [4]    flags: bit7=isLast, bit6=continuation, bit5=compressed
///   [5]    sequence number
///   [6]    record index within response
///   [7]    total records in response
///   [8-15] 8 bytes payload
public enum AAAAEncoder {
    public static let recordSize = 16
    public static let payloadPerRecord = 8
    public static let maxRecords = 8
    public static let maxPayload = maxRecords * payloadPerRecord  // 64 bytes

    /// Encode payload into 1-4 IPv6 addresses
    public static func encode(
        payload: [UInt8], seqNo: UInt8, fragIdx: UInt8, fragTotal: UInt8,
        isLast: Bool, prefix: IPv6Prefix = .random()
    ) -> [[UInt8]] {
        let recordsNeeded = min(max((payload.count + payloadPerRecord - 1) / payloadPerRecord, 1), maxRecords)
        var records = [[UInt8]]()

        for i in 0..<recordsNeeded {
            var ipv6 = [UInt8](repeating: 0, count: recordSize)
            // Prefix
            ipv6[0] = prefix.bytes[0]; ipv6[1] = prefix.bytes[1]
            ipv6[2] = prefix.bytes[2]; ipv6[3] = prefix.bytes[3]
            // Flags
            var flags: UInt8 = 0
            if i == recordsNeeded - 1 && isLast { flags |= 0x80 }
            if i < recordsNeeded - 1 { flags |= 0x40 }
            ipv6[4] = flags
            ipv6[5] = seqNo
            ipv6[6] = UInt8(i)
            ipv6[7] = UInt8(recordsNeeded)
            // Payload
            let start = i * payloadPerRecord
            let end = min(start + payloadPerRecord, payload.count)
            if start < payload.count {
                for j in start..<end {
                    ipv6[8 + (j - start)] = payload[j]
                }
            }
            records.append(ipv6)
        }
        return records
    }

    /// Decode 1-4 IPv6 addresses back to payload
    public static func decode(_ records: [[UInt8]]) throws -> (payload: [UInt8], seqNo: UInt8, isLast: Bool) {
        guard !records.isEmpty else { throw FFError.noRecords }
        guard records[0].count >= recordSize else { throw FFError.recordTooShort }

        let seqNo = records[0][5]
        let isLast = (records[0][4] & 0x80) != 0

        var payload = [UInt8]()
        for record in records {
            guard record.count >= recordSize else { continue }
            payload.append(contentsOf: record[8..<16])
        }
        return (payload, seqNo, isLast)
    }
}
