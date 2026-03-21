import Foundation
import CryptoKit

/// Layered Domain Generation Algorithm
/// Layer 1 (bootstrap): compiled-in seed, used before DISCOVER
/// Layer 2 (epoch): received via DISCOVER, replaces bootstrap
public class DomainManager {
    public var initialSeed: [UInt8]    // 32 bytes
    public var epochSeed: [UInt8]?     // 32 bytes, after DISCOVER
    public var epochNumber: Int = 0
    public var clockOffset: TimeInterval = 0

    /// When set, bypasses DGA entirely and always returns this domain
    public var fixedDomain: String?

    /// Pre-registered domains (must be aged 3+ months)
    public static let domainTable: [String] = [
        "cdn-static-eu.net", "api-metrics-global.org", "cloud-sync-data.net",
        "web-analytics-hub.com", "global-cache-cdn.net", "data-stream-api.org",
        "secure-edge-proxy.net", "fast-content-cdn.com", "api-gateway-cloud.net",
        "metrics-data-hub.org", "edge-compute-api.net", "cdn-asset-global.com",
        // Full 108 domain table loaded from config
    ]

    public static let emergencyDomains: [String] = [
        "global-health-data.org", "climate-research-db.net",
        "open-science-archive.org", "world-education-hub.net",
        "digital-rights-watch.org",
    ]

    public init(seed: [UInt8]) {
        self.initialSeed = seed
    }

    /// Get the active domain for today (with optional day offset for fallback)
    /// If fixedDomain is set, always returns that (bypasses DGA)
    public func activeDomain(offset: Int = 0) -> String {
        if let fixed = fixedDomain, !fixed.isEmpty {
            return fixed
        }
        let seed = epochNumber > 0 ? (epochSeed ?? initialSeed) : initialSeed
        let epoch = epochNumber
        return computeDomain(seed: seed, date: correctedDate(), epoch: epoch, offset: offset)
    }

    /// Full fallback sequence: epoch → bootstrap → emergency
    public func fallbackSequence() -> [String] {
        var domains = [String]()
        let date = correctedDate()

        if epochNumber > 0, let es = epochSeed {
            for offset in [0, 1, -1] {
                domains.append(computeDomain(seed: es, date: date, epoch: epochNumber, offset: offset))
            }
        }

        for offset in [0, 1, -1] {
            domains.append(computeDomain(seed: initialSeed, date: date, epoch: 0, offset: offset))
        }

        domains.append(contentsOf: Self.emergencyDomains)

        // Deduplicate preserving order
        var seen = Set<String>()
        return domains.filter { seen.insert($0).inserted }
    }

    /// Update epoch seed from DISCOVER response
    public func updateEpoch(encryptedSeed: [UInt8], sessionKey: [UInt8]) {
        var decoded = [UInt8](repeating: 0, count: 16)
        for i in 0..<min(16, encryptedSeed.count) {
            decoded[i] = encryptedSeed[i] ^ sessionKey[i]
        }
        let secret = SymmetricKey(data: decoded)
        let expanded = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: secret,
            salt: Data(),
            info: Data("freeflow-epoch-expand".utf8),
            outputByteCount: 32
        )
        epochSeed = expanded.withUnsafeBytes { Array($0) }
        epochNumber += 1
    }

    /// Sync clock with Oracle server time
    public func syncClock(serverTime: UInt32) {
        let serverDate = Date(timeIntervalSince1970: TimeInterval(serverTime))
        clockOffset = serverDate.timeIntervalSince(Date())
    }

    private func correctedDate() -> Date {
        Date().addingTimeInterval(clockOffset)
    }

    private func computeDomain(seed: [UInt8], date: Date, epoch: Int, offset: Int) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd"
        formatter.timeZone = TimeZone(abbreviation: "UTC")
        let adjusted = date.addingTimeInterval(TimeInterval(offset * 86400))
        let dateStr = formatter.string(from: adjusted)

        let input = "\(dateStr)-\(epoch)-\(offset)"
        let key = SymmetricKey(data: seed)
        let mac = HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: key)
        let hashBytes = Array(mac)

        let idx = (UInt32(hashBytes[0]) << 24 | UInt32(hashBytes[1]) << 16 |
                   UInt32(hashBytes[2]) << 8 | UInt32(hashBytes[3])) % UInt32(Self.domainTable.count)
        return Self.domainTable[Int(idx)]
    }
}
