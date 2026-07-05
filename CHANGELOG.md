# Changelog

## v0.1.0-dev

- [Added] Project scaffold with mise toolchain and test-only StreamData dependency
- [Added] Encapsulation header codec with the 8 EtherNet/IP commands and status codes
- [Added] Encapsulation command builders (RegisterSession, SendRRData, SendUnitData, ListIdentity)
- [Added] CPF item codec and ListIdentity identity item (big-endian sockaddr handling)
- [Fixed] CPF decode rejects malformed known items and trailing bytes after item count
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
- [Added] Scanner Unconnected Send routing and get/set attribute helpers
- [Fixed] route_path override test exercises real precedence
- [Added] Scanner NOP keepalive and explicit connection-loss semantics
- [Added] UDP ListIdentity discovery (broadcast and unicast)
- [Fixed] Discovery closes the UDP socket when the initial send fails
- [Added] cpppo interop harness (docker compose + tagged interop tests)
- [Added] CI workflow (format check + tests) on X64 runner
- [Fixed] Scanner send failures stop the session with connection_lost instead of crashing
- [Fixed] Hermetic discovery leak test without DNS; test timing hardening
- [Added] Unconnected Send decode and unknown-command encapsulation replies
- [Added] Adapter skeleton: config, assembly store and owner process
- [Fixed] Adapter start_link returns a clean error for incomplete identity options
- [Added] Adapter message router dispatch, object/handler behaviours and Identity object
- [Added] Assembly object with handler-mediated reads and writes
- [Added] Connection Manager (Unconnected Send), TCP/IP Interface and Ethernet Link objects
