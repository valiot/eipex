# Changelog

## v0.1.0-dev

- [Added] Project scaffold with mise toolchain and test-only StreamData dependency
- [Added] Encapsulation header codec with the 8 EtherNet/IP commands and status codes
- [Added] Encapsulation command builders (RegisterSession, SendRRData, SendUnitData, ListIdentity)
- [Added] CPF item codec and ListIdentity identity item (big-endian sockaddr handling)
- [Fixed] CPF decode rejects malformed known items and trailing bytes after item count
- [Added] EPATH codec: logical, symbolic and port segments with spec padding
