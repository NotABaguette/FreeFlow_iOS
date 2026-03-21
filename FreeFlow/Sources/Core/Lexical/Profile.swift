import Foundation
import CryptoKit

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
        let hash = SHA256.hash(data: publicKey)
        let idx = Int(hash.withUnsafeBytes { $0.load(as: UInt16.self) }) % profiles.count
        return profiles[idx]
    }

    /// Load all profiles from a directory
    public static func loadAll(from directory: URL) -> [LexicalProfile] {
        var profiles = [LexicalProfile]()
        guard let files = try? FileManager.default.contentsOfDirectory(at: directory,
                includingPropertiesForKeys: nil) else { return profiles }
        for file in files where file.pathExtension == "json" {
            if var profile = try? loadProfile(from: file) {
                profile.buildReverseMaps()
                profiles.append(profile)
            }
        }
        return profiles
    }

    /// Load a single profile from a JSON file
    public static func loadProfile(from url: URL) throws -> LexicalProfile {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        var profile = try decoder.decode(LexicalProfile.self, from: data)
        profile.buildReverseMaps()
        return profile
    }

    /// Load profiles bundled in the app or SPM module
    public static func loadBundled() -> [LexicalProfile] {
        var profiles = [LexicalProfile]()

        // Try SPM resource bundle first
        #if SWIFT_PACKAGE
        if let bundleURL = Bundle.module.url(forResource: "profiles", withExtension: nil) {
            profiles = loadAll(from: bundleURL)
            if !profiles.isEmpty { return profiles }
        }
        // Also try individual files in module bundle
        if let urls = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: "profiles") {
            for url in urls {
                if var p = try? loadProfile(from: url) { p.buildReverseMaps(); profiles.append(p) }
            }
            if !profiles.isEmpty { return profiles }
        }
        #endif

        // Try main app bundle
        let searchPaths: [URL?] = [
            Bundle.main.url(forResource: "profiles", withExtension: nil),
            Bundle.main.resourceURL?.appendingPathComponent("profiles"),
            Bundle.main.resourceURL,
        ]
        for path in searchPaths {
            if let p = path {
                let loaded = loadAll(from: p)
                if !loaded.isEmpty { return loaded }
            }
        }

        // Try individual files in main bundle
        if let urls = Bundle.main.urls(forResourcesWithExtension: "json", subdirectory: "profiles")
                ?? Bundle.main.urls(forResourcesWithExtension: "json", subdirectory: nil) {
            for url in urls {
                if var p = try? loadProfile(from: url) { p.buildReverseMaps(); profiles.append(p) }
            }
        }

        return profiles
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

    // Support both Go naming ("word_list", "bits") and explicit ("word_list_key", "bits_used")
    enum CodingKeys: String, CodingKey {
        case wordList = "word_list"
        case wordListKey = "word_list_key"
        case bits = "bits"
        case bitsUsed = "bits_used"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        // Try "word_list" first (Go format), then "word_list_key"
        if let wl = try? container.decode(String.self, forKey: .wordList) {
            wordListKey = wl
        } else {
            wordListKey = try container.decode(String.self, forKey: .wordListKey)
        }
        // Try "bits" first (Go format), then "bits_used"
        if let b = try? container.decode(Int.self, forKey: .bits) {
            bitsUsed = b
        } else {
            bitsUsed = try container.decode(Int.self, forKey: .bitsUsed)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(wordListKey, forKey: .wordList)
        try container.encode(bitsUsed, forKey: .bits)
    }

    public init(wordListKey: String, bitsUsed: Int) {
        self.wordListKey = wordListKey
        self.bitsUsed = bitsUsed
    }
}
