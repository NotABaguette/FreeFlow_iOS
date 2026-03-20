import Foundation

/// Adaptive rate limiter with Poisson jitter
/// Mimics normal DNS traffic patterns to avoid detection
public actor AdaptiveRateLimiter {
    public let baseInterval: TimeInterval = 3.0
    public let maxInterval: TimeInterval = 30.0
    private var currentInterval: TimeInterval = 3.0
    private let poissonLambda: Double = 4.0

    private var dailyBudget = 300
    private var dailyUsed = 0
    private var currentDay: Int

    // 5-minute sliding window for adaptation
    private var windowStart = Date()
    private var windowSuccess = 0
    private var windowTotal = 0

    public init() {
        currentDay = Calendar.current.component(.day, from: Date())
    }

    /// Wait for the next allowed query slot
    public func waitForNext() async throws {
        let today = Calendar.current.component(.day, from: Date())
        if today != currentDay {
            dailyUsed = 0
            currentDay = today
        }
        guard dailyUsed < dailyBudget else { throw FFError.budgetExhausted }

        let jitter = poissonJitter()
        let wait = currentInterval + jitter
        try await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
        dailyUsed += 1
    }

    /// Record query result for adaptive throttling
    public func record(success: Bool) {
        let now = Date()
        if now.timeIntervalSince(windowStart) > 300 {
            evaluateWindow()
            windowStart = now
            windowSuccess = 0
            windowTotal = 0
        }
        windowTotal += 1
        if success { windowSuccess += 1 }
    }

    private func evaluateWindow() {
        guard windowTotal >= 3 else { return }
        let rate = Double(windowSuccess) / Double(windowTotal)
        if rate < 0.7 {
            currentInterval = min(currentInterval * 2, maxInterval)
            dailyBudget = max(dailyBudget * 3 / 4, 50)
        } else if rate > 0.9 {
            currentInterval = max(currentInterval - 0.5, baseInterval)
        }
    }

    private func poissonJitter() -> TimeInterval {
        let u = Double.random(in: 0.0001..<0.9999)
        return -poissonLambda * log(1.0 - u)
    }
}
