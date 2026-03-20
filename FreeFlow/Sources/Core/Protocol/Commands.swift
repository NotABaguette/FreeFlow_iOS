import Foundation

/// FreeFlow command codes
public enum Command: UInt8 {
    case hello       = 0x01
    case getBulletin = 0x02
    case sendMsg     = 0x03
    case getMsg      = 0x04
    case ack         = 0x05
    case discover    = 0x06
    case ping        = 0x07
    case err         = 0xFF

    public var needsSession: Bool {
        switch self {
        case .sendMsg, .getMsg, .ack: return true
        default: return false
        }
    }
}
