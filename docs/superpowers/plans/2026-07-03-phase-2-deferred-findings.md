# Deferred findings from the Phase 1 final review

Carried forward from the whole-branch review of `phase-1-codecs` (35f9f79..f4a7991).
Address during Phase 2 unless noted; none block the Phase 1 merge.

## Fix during Phase 2 work

- **Encap/CPF encode-size guard stragglers:** `Path.words/1` on odd-length hand-built
  binaries floors silently; MSP offsets past 0xFFFF; `Identity` `product_name` > 255
  bytes. Same guard treatment as the fixed sites.
- **Forward Open failure-reply decoder** (triad + remaining path size) — the scanner
  needs it to correlate failed FOs.
- **`MessageRouter.decode_response` strict reserved byte:** hard-matches `0x00`; relax
  to `_reserved` for interop with sloppy devices (decide with a capture in hand).
- **`ConnectionManager.decode_params/decode_transport` raise on wrong-size binaries:**
  safe via `decode_forward_open` today, but as public `decode_*` they should error.
- **`conn_type_name`/`priority_name` return `nil` for reserved bit patterns** — nil
  poisons re-encode; the adapter's FO validation needs explicit handling anyway.
- **Malformed-input tests for CM decoders** (truncated FO/FC/reply payloads).
- **`Logix.decode_template_attributes`:** surface per-attribute non-zero status as
  `{:attr_status, id, status}` instead of collapsing to `:malformed_template`; also
  tolerate/reject trailing bytes consistently with CPF strictness.
- **32-bit symbol instance segment (0x26)** in `encode_symbol_list` for controllers
  with instance IDs beyond 0xFFFF (guard raises today; Phase 6 tag-list iteration
  needs the real format).
- **Error-atom unification pass** before the API goes public: `Types` `:bad_value` vs
  `:malformed_*` elsewhere; CM `:malformed_reply` naming.
- **Port segment encode:** guard rejects only `port > 14`; also reject `port < 1`,
  and add extended port/link (IP link addresses) when routing needs it.

## Phase 7 (docs/polish)

- `@doc` on public functions; per-field struct typespecs (`@type t`) for Dialyzer.
- Broader wrong-length CPF matrix; `:connection_point` segment named test.

## Accepted (no action)

- Scaffold commit carries two CHANGELOG lines (history).
- `unwrap_cpf/1` does not check the frame command (session layer dispatches first).
- Duplicated 6-byte prefix in `send_rr_data`/`send_unit_data` (two obvious lines).
- `Identity.decode_item` ignores `sin_family` (liberal decode; devices ship 0).
- `Path` decode accepts missing trailing pad on final odd symbolic segment (liberal
  decode; some stacks omit it).
- MSP builds via two `IO.iodata_to_binary/1` calls (clarity over cleverness).

# Deferred findings from the Phase 2 final review

Carried forward from the whole-branch review of `phase-2-explicit-scanner`
(2396bc0..145b903). Address in Phase 3+ unless noted.

## Fix during Phase 3/4 work

- **`recv_frame/3` discards bytes after the RegisterSession reply** instead of
  seeding `state.buffer` — a pipelining target would lose frames (real targets
  don't pipeline there; one-line thread-through).
- **Builder raises inside the session kill all queued callers:** a bad
  `data:`/`symbolic:` (>255 chars) raises in the server. Rescue in
  `handle_call({:request, ...})` → `{:error, {:invalid_request, reason}}`, or
  document the blast radius.
- **Unconnected Send tick defaults (~5.1 s) ignore the per-request timeout** and
  violate spec §6's ≥10 s unconnected floor — derive `timeout_ticks` from the
  request timeout when wiring Phase 3/4 (inherited from Phase 1 CM defaults).
- **Docs pass before any Hex release:** `@doc` on all Scanner public functions;
  document time-on-wire timeout semantics (queued requests wait longer
  end-to-end) and the `{:shutdown, :connection_lost}` link contract
  (supervise or trap exits); add `route_path` to the moduledoc.

## Accepted (no action)

- Keepalive timer left running at shutdown (message to dead pid is a no-op).
- `for` comprehension used for reply side effects in `fail_callers`.
- NOP-interval test timing slack (bump sleep only if CI flakes).
- `discover` defdelegate placement; loose `{:error, term()}` helper specs.
- New callers racing a dying scanner get standard OTP `:noproc`/exit semantics
  (only already-queued callers are guaranteed clean error tuples).
