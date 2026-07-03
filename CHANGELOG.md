# Changelog

## v0.1.0-dev

- [Added] Scanner Unconnected Send routing and get/set attribute helpers
- [Added] Project scaffold with mise toolchain and test-only StreamData dependency
- [Added] Encapsulation header codec with the 8 EtherNet/IP commands and status codes
- [Added] Encapsulation command builders (RegisterSession, SendRRData, SendUnitData, ListIdentity)
- [Added] CPF item codec and ListIdentity identity item (big-endian sockaddr handling)
- [Fixed] CPF decode rejects malformed known items and trailing bytes after item count
- [Fixed] route_path override test exercises real precedence
- [Added] EPATH codec: logical, symbolic and port segments with spec padding
- [Fixed] EPATH symbolic encode raises on names longer than 255 bytes
- [Added] Message Router request/response codec with CIP general status table
- [Added] CIP elementary type codec and Logix 16-bit symbol type decoder
- [Fixed] 64-bit type encode rejects out-of-range integers instead of truncating
- [Added] Connection Manager codec: Forward Open/Close, Unconnected Send, conn params
- [Fixed] Connection params encode rejects out-of-range sizes instead of masking
- [Added] Logix services codec: tag read/write, RMW, MSP, symbol list, templates
- [Fixed] Template attribute decode returns error on unexpected attribute ids
- [Fixed] Non-finite float decode, unknown encap command context, encode size guards
- [Added] Property-based roundtrip tests for EPATH and CIP types
- [Added] Scanner session lifecycle (RegisterSession over TCP) and scripted test target
- [Added] Scanner generic_message: UCMM requests with correlation, queueing and timeouts
- [Fixed] generic_message outer call waits on the server-side request timer
