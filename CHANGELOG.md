# Changelog

## v0.2.0 — 2026-11-06

Multicast class 1 I/O in the T→O direction, in both roles — the transport
Omron tag data links (and any multicast producer) use. O→T stays
point-to-point; shared multicast streams and ODVA IP-derived group
allocation remain deferred (see Known limitations in the README).

### Added

- **Scanner**: `open_io/2` accepts `type: :multicast` (plus `interface:` for
  the IGMP join) on `:t_to_o`. The scanner joins the multicast group the
  target announces in its Forward Open reply — on a socket bound to the
  group address, so it never intercepts unicast traffic on the shared
  port — and consumes production from it. A reply without a usable group
  fails the open with `:no_multicast_sockaddr` and releases the accepted
  connection with a Forward Close. `type: :multicast` on `:o_to_t` is
  refused locally (`:o2t_multicast_unsupported`).
- **Adapter**: a Forward Open with a multicast T→O is accepted (O→T
  multicast still answers 0x01/0x0123). The adapter assigns the T→O
  connection ID, announces the configured group in the reply's
  `sockaddr_t2o`, and produces to it. New `io` option:
  `multicast: [group:, interface:, ttl:]` (defaults
  `{239, 192, 1, 0}` / `{0, 0, 0, 0}` / `1`).

### Changed

- **Scanner**: the class 1 T→O connection ID is now taken from the Forward
  Open reply instead of the request — the target owns that ID for multicast
  connections, and echoes it for point-to-point ones.

## v0.1.0 — 2026-07-06

First public release: a pure-Elixir EtherNet/IP (CIP) stack with scanner and
adapter roles, explicit + class 1 implicit messaging, and Logix tag services.

### Added

- **Project**: pure-Elixir scaffold (mise toolchain, zero runtime deps) and a
  CI workflow (format check + tests) on the X64 runner.
- **Codecs**: encapsulation header and the 8 EtherNet/IP commands
  (RegisterSession, SendRRData, SendUnitData, ListIdentity, Unconnected Send)
  with status codes and unknown-command handling; CPF item codec and
  ListIdentity identity item; EPATH codec (logical, symbolic and port
  segments); CIP Message Router request/response codec with the general
  status table; CIP elementary type codec and the Logix 16-bit symbol type
  decoder; Connection Manager codec (Forward Open/Close, Unconnected Send,
  connection parameters, Forward Close reply and Forward Open error replies);
  Logix services codec (tag read/write, read-modify-write, Multiple Service
  Packet, symbol list, templates).
- **Scanner** (originator): session lifecycle over TCP; `generic_message`
  UCMM requests with correlation, queueing and timeouts; Unconnected Send
  routing and get/set attribute helpers; NOP keepalive and explicit
  connection-loss semantics; UDP ListIdentity discovery (broadcast and
  unicast); Multiple Service Packet batching; Forward Open/Close with
  large-to-standard fallback; connected (class 3) requests over
  SendUnitData; class 1 I/O connections (`open_io`) with cyclic production
  and owner notifications.
- **Adapter** (target): config, assembly store and owner process skeleton;
  message router dispatch with object/handler behaviours; Identity,
  Assembly, Connection Manager, TCP/IP Interface and Ethernet Link objects;
  TCP listener and session handler; UDP ListIdentity discovery responder with
  anti-storm delay; class 3 Forward Open/Close with a connection table,
  capacity limits, sequence dedup and reply caching; class 1 I/O connections
  (cyclic production, watchdog, run/idle) over a shared UDP socket (CPF
  sockaddr extras for I/O exchange) with connection-id demux; exclusive-owner
  conflict detection and randomized I/O connection ids.
- **Logix tag services**: value layer (struct/array/string decode, atomic
  write encode); `tag_list` Symbol Object discovery with UDT template fetch;
  typed `read` (bulk Multiple Service Packet with auto fragmentation); typed
  `write` with type inference from catalog or value; tag path parsing for
  element and member addressing (`Tag[i]`, `A.B`).
- **Testing**: property-based roundtrip tests for EPATH and CIP types;
  cross-role loopback matrices (explicit, connected and class 1 I/O);
  docker-gated interop harnesses against cpppo, pycomm3 and OpENer (excluded
  by default).
- **Docs & packaging**: package metadata, Apache-2.0 LICENSE and
  ex_doc-generated documentation; a library overview moduledoc; a sample
  adapter EDS; a hex-ready README (install, feature matrix, known
  limitations).

### Fixed

- Codecs return `{:error, reason}` instead of raising or silently truncating
  on malformed or out-of-range input: CPF item/trailing-byte validation,
  EPATH symbolic name length guard, 64-bit and connection-parameter range
  checks, non-finite float decode, unknown encapsulation commands, and Logix
  template attribute decode.
- Scanner: send and discovery-socket failures stop the session with an
  explicit `{:shutdown, :connection_lost}` instead of crashing;
  `generic_message` correlates on the server-side request timer;
  RegisterSession rejects unsupported protocol versions; pipelined bytes,
  invalid requests and derived timeout ticks are handled without corrupting
  session state.
- Adapter: `start_link` returns a clean error for incomplete identity
  options; the session handler discards frames pipelined after
  UnregisterSession and tears sessions down cleanly; the TCP acceptor backs
  off on repeated accept errors; the discovery responder survives stray and
  `udp_error` messages and advertises the configured IP and resolved TCP
  port.
- Connected messaging: Forward Open/Close edge cases (large-to-standard
  fallback guard, 0x0107 close handling, variant validation), reply-cache
  purge on close, and class 1 Forward Open via Unconnected Send resolving
  the real peer instead of localhost.
- Class 1 I/O: the scanner-side I/O connection's best-effort Forward Close
  tolerates an already-dead scanner; the adapter session handler survives a
  peer reset between accept and activation and enforces zeroed RegisterSession
  option flags.
- Logix: struct decode reads array members as element lists; `tag_list`
  rejects empty/degenerate partial-transfer replies and guards malformed
  template and symbol-list chunks; bulk read accounts for Multiple Service
  Packet framing overhead with a fallback path; write validates explicit,
  catalog and inferred types; UDT BOOL member bit index is read from the
  member info field rather than the type word.
