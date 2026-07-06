# Deferred findings from the Phase 4 final review

Carried forward from the whole-branch review of `phase-4-connected-messaging`
(1a1ec59..fea81c1). Address during Phase 5+ unless noted.

## Fix during Phase 5 work

- **ConnectionTable under UDP demux load:** every connected lookup serializes
  through one GenServer — consider ETS with read concurrency for `lookup_o2t`
  once class 1 UDP demux multiplies lookup rate. Also: monotonic o2t ids are
  predictable — connection ids demux unauthenticated UDP in class 1, consider
  randomized ids then.
- **Class 3 per-connection watchdog:** absorb class 3 into the Phase 5
  connection gen_statem (or explicitly keep the documented session-lifetime
  deviation — decide when the statem lands).
- **conn_replies purge on session-crash paths:** the purge message covers
  Forward Close; a Phase 5 statem owning connection lifecycle supersedes it.
- **`decode_forward_open_error/1` is exported and tested but unwired** — wire
  into `settle_reply` for triad confirmation on FO errors, or keep as public
  codec API with a doc note.
- **Codec leniency asymmetry:** `decode_forward_close_reply` ignores app-words
  consistency; unify with `decode_forward_open_reply` strictness if the codec
  is touched.
- **Carried from Phase 3 (still open):** instance-0 class-level addressing;
  Unconnected Send multi-hop route validation; unicast ListIdentity skips the
  anti-storm delay; Assembly/network-object status precision (0x03/0x15);
  TcpIpInterface attr-5 odd-length domain pad; AssemblyStore option-validation
  symmetry; kill-based crash-isolation test; spec §3 doc sync.

## Accepted (no action)

- FO wire timeout (~10.24 s) can exceed the local 5 s default timer — inherent
  protocol characteristic, now documented in `@doc forward_open`.
- ConnectionTable monitor retained until session death after last unregister
  (bounded by live sessions).
- `_app_reply`/`_rest` naming asymmetry; generic `:malformed_reply` atom.
- Fallback Forward Open consumes a fresh connection serial (spec-legitimate;
  matches pycomm3 behavior).
- Task-report wording nits (trap_exit "race" label).
