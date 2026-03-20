import Foundation

/// Encodes payloads into natural-looking domain labels using lexical profiles
public struct LexicalEncoder {
    public static let nonceBits = 10

    /// Encode payload → single domain label
    public static func encode(payload: [UInt8], profile: LexicalProfile) throws -> String {
        let nonce = UInt16.random(in: 0..<(1 << nonceBits))

        let payloadBits = bytesToBits(payload)
        let requiredBits = payloadBits.count + nonceBits

        guard let template = profile.templates.first(where: { $0.totalBits >= requiredBits }) else {
            throw FFError.payloadTooLarge
        }

        let templateBits = template.totalBits
        let paddingCount = templateBits - payloadBits.count - nonceBits

        var bits = payloadBits
        bits.append(contentsOf: [Int](repeating: 0, count: paddingCount))
        for i in stride(from: nonceBits - 1, through: 0, by: -1) {
            bits.append((Int(nonce) >> i) & 1)
        }

        var words = [String]()
        var bitPos = 0
        for slot in template.slots {
            guard let wordList = profile.wordLists[slot.wordListKey], !wordList.isEmpty else { continue }
            var index = 0
            for _ in 0..<slot.bitsUsed {
                index = (index << 1) | bits[bitPos]
                bitPos += 1
            }
            index = index % wordList.count
            words.append(wordList[index])
        }

        return words.joined(separator: template.separator)
    }

    /// Encode payload into full query name (label.domain)
    public static func encodeQuery(payload: [UInt8], domain: String, profile: LexicalProfile) throws -> String {
        let label = try encode(payload: payload, profile: profile)
        return label + "." + domain
    }
}

/// Decodes domain labels back to payloads
public struct LexicalDecoder {

    public static func decode(label: String, profile: LexicalProfile) throws -> [UInt8] {
        for template in profile.templates {
            guard let sep = template.separator.first else { continue }
            let words = label.lowercased().split(separator: sep, omittingEmptySubsequences: false).map(String.init)
            guard words.count == template.slots.count else { continue }

            var bits = [Int]()
            var matched = true
            for (i, word) in words.enumerated() {
                let slot = template.slots[i]
                guard let reverseMap = profile.reverseMaps[slot.wordListKey],
                      let index = reverseMap[word] else { matched = false; break }

                for b in stride(from: slot.bitsUsed - 1, through: 0, by: -1) {
                    bits.append((index >> b) & 1)
                }
            }

            guard matched else { continue }
            guard bits.count >= LexicalEncoder.nonceBits else { continue }

            let payloadBits = Array(bits.dropLast(LexicalEncoder.nonceBits))
            return bitsToBytes(payloadBits)
        }
        throw FFError.noTemplateMatched
    }

    public static func decodeQuery(queryName: String, domain: String, profile: LexicalProfile) throws -> [UInt8] {
        let suffix = "." + domain.lowercased()
        let normalized = queryName.lowercased().trimmingCharacters(in: .init(charactersIn: "."))
        guard normalized.hasSuffix(suffix.trimmingCharacters(in: .init(charactersIn: "."))) else {
            throw FFError.wrongDomain
        }
        let subdomain = String(normalized.dropLast(domain.count + 1))
        let labels = subdomain.split(separator: ".").map(String.init)

        if labels.count == 1 {
            return try decode(label: labels[0], profile: profile)
        } else {
            var result = [UInt8]()
            for label in labels {
                result.append(contentsOf: try decode(label: label, profile: profile))
            }
            return result
        }
    }
}

// MARK: - Bit Helpers

func bytesToBits(_ data: [UInt8]) -> [Int] {
    var bits = [Int]()
    bits.reserveCapacity(data.count * 8)
    for byte in data {
        for i in stride(from: 7, through: 0, by: -1) {
            bits.append(Int((byte >> i) & 1))
        }
    }
    return bits
}

func bitsToBytes(_ bits: [Int]) -> [UInt8] {
    let count = (bits.count + 7) / 8
    var result = [UInt8](repeating: 0, count: count)
    for (i, bit) in bits.enumerated() {
        if bit == 1 {
            result[i / 8] |= 1 << (7 - (i % 8))
        }
    }
    return result
}
