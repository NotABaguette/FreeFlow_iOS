import Foundation

/// A lexical encoding profile — maps payload bits to natural-looking domain labels
public struct LexicalProfile: Codable {
    public let id: String
    public let category: String
    public var templates: [LexicalTemplate]
    public var wordLists: [String: [String]]

    /// Reverse lookup maps, built after loading
    public var reverseMaps: [String: [String: Int]] = [:]

    enum CodingKeys: String, CodingKey {
        case id, category, templates, wordLists = "word_lists"
    }

    public mutating func buildReverseMaps() {
        reverseMaps = [:]
        for (key, words) in wordLists {
            var map = [String: Int]()
            for (index, word) in words.enumerated() {
                map[word.lowercased()] = index
            }
            reverseMaps[key] = map
        }
    }

    /// Select profile deterministically from client public key
    public static func assign(publicKey: [UInt8], profiles: [LexicalProfile]) -> LexicalProfile {
        guard !profiles.isEmpty else { fatalError("No profiles loaded") }
        let hash = publicKey.withUnsafeBufferPointer { buf in
            var hasher = Hasher()
            hasher.combine(bytes: UnsafeRawBufferPointer(buf))
            return hasher.finalize()
        }
        return profiles[abs(hash) % profiles.count]
    }
}

public struct LexicalTemplate: Codable {
    public let slots: [LexicalSlot]
    public let separator: String

    public var totalBits: Int {
        slots.reduce(0) { $0 + $1.bitsUsed }
    }
}

public struct LexicalSlot: Codable {
    public let wordListKey: String
    public let bitsUsed: Int

    enum CodingKeys: String, CodingKey {
        case wordListKey = "word_list_key"
        case bitsUsed = "bits_used"
    }
}
