# FreeFlow iOS Client

iOS implementation of the FreeFlow DNS-based covert messaging protocol.

## Tech Stack

- **Swift 5.9+**, iOS 16+
- **CryptoKit** — X25519 ECDH, ChaCha20-Poly1305, Ed25519, SHA256, HMAC, HKDF
- **Network.framework** — UDP DNS queries
- **SwiftUI** — UI (planned)
- **Swift Package Manager**

## Structure

```
FreeFlow/Sources/Core/
├── Protocol/
│   ├── Commands.swift       — 8 command codes (HELLO, PING, SEND_MSG, etc.)
│   ├── Frame.swift          — Wire format: [cmd][seq][frag_idx][frag_total][token(4)][data]
│   └── AAAAEncoder.swift    — IPv6 response encoding with CDN prefixes
├── Crypto/
│   ├── Keys.swift           — X25519 + Ed25519 key generation
│   ├── Session.swift        — HKDF key derivation, ChaCha20-Poly1305, HELLO assembly
│   ├── E2E.swift            — End-to-end encryption between users
│   └── Signing.swift        — Ed25519 bulletin verification
├── Lexical/
│   ├── Profile.swift        — Profile structure, templates, word lists
│   └── Encoder.swift        — Lexical steganographic encoding/decoding
├── DGA/
│   └── DomainManager.swift  — Layered DGA (bootstrap + epoch seeds)
├── Identity/
│   └── Identity.swift       — User identity, fingerprints, contact book
└── Client/
    ├── Connection.swift     — Main connection manager, DNS transport, all operations
    └── RateLimiter.swift    — Adaptive Poisson-jittered rate limiting
```

## Build

```bash
swift build
swift test
```

Or open in Xcode as a Swift Package.

## Protocol Compatibility

Byte-level compatible with the Go Oracle server at `/root/Claude/FreeFlow/`.
Same crypto primitives, frame format, AAAA encoding, lexical profiles.

## Key Operations

- `ping()` — Liveness check + clock sync
- `connect()` — 4-query HELLO handshake, establishes ChaCha20 session
- `sendMessage(_:to:)` — E2E encrypted message via fragmented SEND_MSG
- `pollMessages()` — Poll inbox via GET_MSG
- `getBulletin()` — Fetch Ed25519-signed broadcasts
- `discover()` — Get new epoch seed for DGA domain rotation
