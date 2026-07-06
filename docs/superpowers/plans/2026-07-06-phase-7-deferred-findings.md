# Deferred findings from the Phase 6 final review

Carried forward from the whole-branch review of `phase-6-logix-services`
(b142c8e..8fe1e63). Address during Phase 7+ unless noted.

## Fix during Phase 7 work

- **BOOL-in-UDT bit source** — `Value.decode_member`'s bool clause reads
  `bool_position` from the member's *symbol type word*
  (`Types.decode_symbol_type/1`, bits 8-10) rather than a separate per-member
  `info`-field bit; 1756-PM020 is ambiguous on which field a bit-packed BOOL
  member inside a UDT actually uses on real hardware, and this can't be
  settled by loopback alone. Marked at the call site with
  `# TODO(phase-7): verify BOOL-in-UDT bit source against pycomm3/hardware`
  in `lib/eipex/scanner/logix/value.ex`.
- **Struct-array element lists** — `Logix.resolve_type/2` classifies an array
  of structs as `{:array, {:struct, handle}, dims}`, but
  `Value.decode_member`/`decode_struct` have no per-element struct-array
  decode path yet (only atomic-element arrays are decoded as lists).
- **LEN-vs-capacity bound for Logix STRING** — `Value.decode_string` trusts
  the wire `LEN` value up to the `DATA` member's declared capacity but
  doesn't clamp/validate `LEN <= capacity` before slicing.
- **Fragment reassembly has no absolute cap** — `read_fragments`/
  `fragment_loop` in `Eipex.Scanner.Logix` accumulate indefinitely as long as
  each continuation makes byte progress; a misbehaving device could still
  drive unbounded memory growth via a very long, always-progressing
  fragmented reply. Consider a max-size guard.
- **Perf niggles** (fine at today's tag-catalog sizes; revisit if profiling
  shows it matters) — `fetch_symbols/3`'s `acc ++ symbols` is quadratic in
  the number of continuation chunks; `tag_estimate/2`'s `Enum.find/2` over
  `catalog.tags` is O(n) per tag name for every tag in a bulk read/write.
- **Constant dedup** — `@template_attrs` and the MSP framing-overhead
  constants are duplicated between `Eipex.CIP.Logix` and
  `Eipex.Scanner.Logix`; low value to unify now.
- **Nesting/short-body value tests** — `Value`'s `@max_nesting` boundary
  (a 3-level-deep struct member returning `:nesting_too_deep`) and `slice/3`'s
  `:short_body` error path are exercised only indirectly; no dedicated unit
  test pins either.
- **`test/interop/cpppo_logix_test.exs` moduledoc is now stale** — its
  "cpppo reality" note says `Scanner.Logix.read/2`/`write/3` always send the
  tag name as one opaque symbolic segment, so `"SCADA[0]"` can't be
  resolved. That's no longer true: `Eipex.Scanner.Logix.tag_path/1` (added
  this review) parses `"SCADA[0]"` into a symbolic + member EPATH segment
  pair before every read/write. Docker wasn't re-run in this fix wave to
  verify cpppo's actual behavior against the new wire path, so the interop
  test/doc was deliberately left as-is rather than guessed at — revisit with
  a live cpppo run.

## Accepted (no action)

(none newly accepted this review)

## Added from the Phase 6 fix-wave re-review (low severity, polish)

- **Dotted names with an empty part** (`"A..B"`, `"Tag."`) now return
  `{:error, {:invalid_request, "no function clause..."}}` from the rescued
  `Path.encode` empty-symbolic miss — a clean error tuple but an exception
  string rather than a semantic reason. Give the tag-path parser an explicit
  empty-part rejection with a named reason.
- **Bracketed index ≥ 2^32** (`"Tag[4294967296]"`) truncates silently in the
  32-bit member segment encode. Range-clamp/guard in the parser or encode.
  Far beyond any real Logix dimension.
