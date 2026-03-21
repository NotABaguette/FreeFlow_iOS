import Foundation

/// Proquint encoding: converts binary data to pronounceable CVCVC words.
/// Each 16-bit value → 5-character word. Words joined with "-".
/// A DNS label (max 63 chars) holds 10 words (59 chars) = 20 bytes.
///
/// Consonant table (4 bits → 1 char): b d f g h j k l m n p r s t v z
/// Vowel table (2 bits → 1 char): a i o u
public enum Proquint {
    private static let consonants: [Character] = ["b","d","f","g","h","j","k","l","m","n","p","r","s","t","v","z"]
    private static let vowels: [Character] = ["a","i","o","u"]

    /// Max bytes per DNS label (10 words × 2 bytes = 20)
    public static let maxBytesPerLabel = 20

    // Reverse lookup tables
    private static let consonantIdx: [Character: Int] = {
        var m = [Character: Int]()
        for (i, c) in consonants.enumerated() { m[c] = i }
        return m
    }()
    private static let vowelIdx: [Character: Int] = {
        var m = [Character: Int]()
        for (i, v) in vowels.enumerated() { m[v] = i }
        return m
    }()

    /// Encode binary data to proquint string.
    /// If data has odd length, pads with 0x00.
    public static func encode(_ data: [UInt8]) -> String {
        var padded = data
        if padded.count % 2 != 0 {
            padded.append(0)
        }

        var words = [String]()
        for i in stride(from: 0, to: padded.count, by: 2) {
            let val = UInt16(padded[i]) << 8 | UInt16(padded[i + 1])
            words.append(encodeWord(val))
        }
        return words.joined(separator: "-")
    }

    /// Decode proquint string back to binary data.
    public static func decode(_ s: String) throws -> [UInt8] {
        guard !s.isEmpty else { return [] }
        let words = s.split(separator: "-").map(String.init)
        var data = [UInt8]()
        for w in words {
            let val = try decodeWord(w)
            data.append(UInt8(val >> 8))
            data.append(UInt8(val & 0xFF))
        }
        return data
    }

    /// Check if a DNS label looks like proquint (multiple CVCVC words separated by -)
    public static func isProquint(_ label: String) -> Bool {
        let words = label.split(separator: "-")
        guard words.count >= 2 else { return false }
        for w in words {
            guard w.count == 5 else { return false }
            let chars = Array(w)
            guard consonantIdx[chars[0]] != nil,
                  vowelIdx[chars[1]] != nil,
                  consonantIdx[chars[2]] != nil,
                  vowelIdx[chars[3]] != nil,
                  consonantIdx[chars[4]] != nil else { return false }
        }
        return true
    }

    private static func encodeWord(_ val: UInt16) -> String {
        var buf = [Character](repeating: "x", count: 5)
        buf[0] = consonants[Int((val >> 12) & 0x0F)]
        buf[1] = vowels[Int((val >> 10) & 0x03)]
        buf[2] = consonants[Int((val >> 6) & 0x0F)]
        buf[3] = vowels[Int((val >> 4) & 0x03)]
        buf[4] = consonants[Int(val & 0x0F)]
        return String(buf)
    }

    private static func decodeWord(_ w: String) throws -> UInt16 {
        let chars = Array(w)
        guard chars.count == 5 else { throw FFError.frameTooShort(chars.count) }

        guard let c0 = consonantIdx[chars[0]],
              let v0 = vowelIdx[chars[1]],
              let c1 = consonantIdx[chars[2]],
              let v1 = vowelIdx[chars[3]],
              let c2 = consonantIdx[chars[4]] else {
            throw FFError.decryptionFailed
        }

        return UInt16(c0) << 12 | UInt16(v0) << 10 | UInt16(c1) << 6 | UInt16(v1) << 4 | UInt16(c2)
    }
}
