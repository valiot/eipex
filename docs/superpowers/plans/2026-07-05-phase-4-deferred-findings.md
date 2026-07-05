# Deferred findings from the Phase 3 final review

Carried forward from the whole-branch review of `phase-3-explicit-adapter`
(b739e7b..d64aaff). Address during Phase 4+ unless noted.

## Fix during Phase 4/5 work

- **Narrow the scanner's request rescue** (`Eipex.Scanner.handle_call({:request, ...})`)
  to wrap only `build_request/2` — today it also covers send/queueing, so a future
  bug there would masquerade as `{:invalid_request, _}`.
- **Instance-0 class-level addressing:** objects only match instance 1; Get_Attribute_Single
  on instance 0 attr 1 (class revision) is a common conformance probe → answer it.
- **RegisterSession protocol-version check:** version ≠ 1 should answer encap status
  0x0069 with the supported version instead of being accepted.
- **Unconnected Send route-path validation:** multi-hop routes are silently processed
  locally; validate or explicitly document single-hop-only.
- **Unicast ListIdentity replies skip the anti-storm delay** (ODVA recommends delay
  for broadcast only); tight third-party discover timeouts could miss the adapter.
- **Assembly/network-object status precision:** GET with trailing data → 0x03/0x15
  instead of 0x08; instance-first checking on unknown-instance-with-data.
- **TcpIpInterface attr 5:** odd-length domain names need the STRING pad byte.
- **AssemblyStore/adapter option validation symmetry:** malformed `assemblies:` spec
  surfaces as `{:error, {%KeyError{}, _}}` — validate like identity options.
- **Kill-based crash-isolation test** for session handlers (`Process.exit(handler, :kill)`).
- **Test the Assembly refresh write-failure fallback and set-path unknown attr/instance.**
- **Spec §3 doc sync:** implementation follows the plan's revisions (Adapter as owner
  GenServer, AssemblyStore as GenServer, Object without class_code/0) — update the
  spec so both documents agree.

## Accepted (no action)

- Nested Unconnected Send depth unbounded but proven finite (≥10 B/level, 64 KiB cap).
- Dispatch rescue covers response encoding (same bug class as object crash; 0x1F fine).
- SessionHandler `reply/2` ignores send errors (bounded until tcp_closed).
- Inactivity/keepalive timers not cancelled on stop paths (no-op to dead pid).
- Adapter tests use plain start_link without teardown (test-process link cleans up).
- Identity fallthrough coarse on shape mismatches; `kind` atom unvalidated in store.
