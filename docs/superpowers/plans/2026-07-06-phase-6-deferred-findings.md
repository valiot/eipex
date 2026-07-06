# Deferred findings from the Phase 5 final review

Carried forward from the whole-branch review of `phase-5-implicit-io`
(e79052b..345cbd0). Address during Phase 6+ unless noted.

## Fix during Phase 6 work

- **Exclusive-owner check TOCTOU:** `validate_no_conflict` (open_io) and
  `ConnectionTable.register` are separate GenServer calls — two concurrent FOs
  from different sessions targeting the same o2t assembly could both pass the
  ownership scan before either registers, admitting two owners. Move the
  conflict check INTO `register` (atomic) to close it.
- **Handler I/O-path ctx is `%{}`** while the explicit path passes
  config/store/session — a handler reading `ctx.store` works on one path,
  crashes the io statem on the other; and handler exceptions on the I/O path
  have no rescue (unlike MessageRouter). Pass `conn_info` as ctx and/or wrap.
- **`close/1`/`set_output/2` on a stopped io statem exit `:noproc`** — the
  watchdog race is user-reachable; a `try/catch :exit` in `close/1` makes it
  idempotent.
- **32-bit sequence-boundary property test** for `seq_newer?`/production under
  traffic (currently example-tested only).
- **Carried from Phase 4 (still open):** ConnectionTable ETS/read-concurrency
  under UDP demux load; `decode_forward_open_error` unwired; codec leniency
  asymmetry.
- **Carried from Phase 3 (still open):** instance-0 class addressing; multi-hop
  route validation; unicast ListIdentity anti-storm delay; Assembly/network
  status precision; TcpIpInterface attr-5 pad; AssemblyStore option validation;
  kill-based crash-isolation test.
- **Spec §5 doc bugs (Phase 7 doc pass):** watchdog stated "RPI × 2^multiplier"
  (code/CIP = 4 << code); spec still names Registry/Adapter.Connection and
  claims input-only/listen-only "supported" — add deferral notes.

## Accepted (no action)

- `resolve_peer` duplicated scanner/adapter (different fallback semantics).
- Redundant per-test setup adapter; test adapters not explicitly stopped
  (linked to test process, die with it).
- Produce timer drift (period = RPI + handling; absorbed by 4× watchdog).
- 16-bit sequence count decoded but unused (seq32 subsumes dedup).
- Fixed Process.sleep in opener interop (single, against 100ms-RPI peer).

## Deferred protocol scope (whole features, not defects)

- **Multicast** connection types (allocation, IGMP join, master handoff) —
  currently refused with 0x0123/0x0124.
- **Input-only / listen-only** heartbeat connection points and cascade closes —
  currently fail size validation (a refusal).
- **Config-data segments** in the connection path.
