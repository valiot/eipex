# Eipex — EtherNet/IP stack in Elixir (scanner + adapter)

**Date:** 2026-07-02
**Status:** approved (design validated in brainstorming session)
**Repo:** `valiot/eipex` · **Hex package:** `eipex` · **Root module:** `Eipex`

## 1. Goal

Implement a complete EtherNet/IP protocol stack (encapsulation + CIP) in pure
Elixir, covering both roles:

- **Scanner (originator):** client that discovers devices, sends explicit
  messaging (UCMM and connected class 3), opens class 1 implicit I/O
  connections, and speaks Rockwell's Logix services (tags, UDTs) for
  ControlLogix/CompactLogix/Micro800 PLCs.
- **Adapter (target):** server/device that exposes identity, assemblies and CIP
  objects; accepts sessions, explicit messaging and class 1 implicit I/O
  connections from PLCs or other scanners.

No EtherNet/IP adapter exists in Elixir/Erlang (verified on hex.pm and GitHub);
the only scanner is `scrub` (basic originator, never published to hex). Eipex
replaces `scrub` and, mid-term, `abex`/libplctag (C NIF).

### Out of scope (v1)

- Secure EtherNet/IP (DTLS, `START_DTLS` command 0x00C8) and CIP Security.
- CIP Safety, CIP Motion, CIP Sync.
- Class 0 originator role (raw, no sequence count) — only classes 1 and 3.
- Redundant owner connections.
- DLR (Device Level Ring) and advanced QoS (configurable DSCP stays a static
  attribute).
- Magic auto-reconnect in the scanner (the app decides when to retry).
- Symbol/Template object emulation in the adapter (it is not a Logix PLC).

## 2. Architecture decisions

| Decision | Choice | Rationale |
|---|---|---|
| Packaging | Single layered library (`modbux` style) | Majestic monolith; no second consumer justifies multi-package |
| Dependencies | Zero at runtime (OTP `gen_tcp`/`gen_udp`/`gen_statem`); test-only deps allowed | Valiot convention (modbux), simplicity on Nerves |
| Codecs | Pure `encode/decode` functions, no processes | Testable against byte vectors; native binary pattern matching |
| CIP connections | One `gen_statem` per connection with the spec's literal states | Per-process timers (RPI, watchdog), no global 10 ms tick like OpENer |
| Object dispatch | `%{class_code => module}` map + one behaviour per CIP class | Users add vendor-specific objects without touching the library |
| App integration | `Eipex.Adapter.Handler` behaviour (callbacks) | OTP equivalent of OpENer's callbacks |
| UDP I/O | One socket 2222 per role, demuxed by connection ID via `Registry` | Cyclic traffic never funnels through a central GenServer |
| Network errors | Codecs return `{:error, _}`, never raise on malformed input | The adapter answers the correct CIP status instead of crashing (lesson from OpENer's CVEs) |

## 3. Module structure

```
eipex
├── Layer 0 — Pure codecs (no processes)
│   ├── Eipex.Encap                 # 24B header + 8 commands + status codes
│   ├── Eipex.CPF                   # CPF items (sockaddr in big-endian: sole exception to LE)
│   ├── Eipex.CIP.Path              # EPATH: logical/symbolic/port segments + padding
│   ├── Eipex.CIP.MessageRouter     # MR request/response + general status codes
│   ├── Eipex.CIP.Types             # CIP elementary types + Logix symbol type + structs
│   ├── Eipex.CIP.ConnectionManager # FO/LFO/FC/UnconnectedSend + 16/32-bit conn params
│   └── Eipex.CIP.Logix             # Read/Write Tag (frag), RMW, MSP, Symbol 0x6B, Template 0x6C
│
├── Layer 1 — Scanner role (originator)
│   ├── Eipex.Scanner               # session GenServer + explicit API + discover
│   ├── Eipex.Scanner.Logix         # tags/UDTs with automatic fragmentation and MSP
│   └── Eipex.Scanner.IOConnection  # class 1 gen_statem (O→T production, T→O watchdog)
│
└── Layer 2 — Adapter role (target)
    ├── Eipex.Adapter               # supervisor + config + public API
    ├── Eipex.Adapter.Listener      # gen_tcp acceptor → DynamicSupervisor of handlers
    ├── Eipex.Adapter.SessionHandler# GenServer per TCP connection (framing, sessions, 120s timeout)
    ├── Eipex.Adapter.MessageRouter # dispatch to objects by class code
    ├── Eipex.Adapter.Object        # CIP class behaviour
    ├── Eipex.Adapter.Object.{Identity, Assembly, ConnectionManager,
    │                          TcpIpInterface, EthernetLink}
    ├── Eipex.Adapter.AssemblyStore # ETS: buffers per assembly instance
    ├── Eipex.Adapter.Connection    # gen_statem per class 1/3 connection
    ├── Eipex.Adapter.UDP           # socket 2222, demux by connection ID, multicast
    └── Eipex.Adapter.Discovery     # UDP 44818: ListIdentity with random delay
```

## 4. Public API (sketch)

### Scanner

```elixir
{:ok, scanner} = Eipex.Scanner.start_link(host: "192.168.1.10")
# opts: port (44818), route_path ([backplane: slot] | :none), timeout, socket_opts

{:ok, devices} = Eipex.Scanner.discover()          # ListIdentity broadcast, list of Identity items

# Escape valve, pycomm3-generic_message style — any CIP service:
{:ok, resp} = Eipex.Scanner.generic_message(scanner,
  service: 0x0E, class: 0x01, instance: 1, attribute: 7)
# opts: connected: true | false (UCMM), route_path override, data: binary

{:ok, conn} = Eipex.Scanner.forward_open(scanner, transport_class: 3)
:ok = Eipex.Scanner.forward_close(scanner, conn)

# Class 1 implicit I/O:
{:ok, io} = Eipex.Scanner.open_io(scanner,
  o_to_t: [assembly: 150, size: 32, rpi: 10_000, run_idle: true, type: :point_to_point],
  t_to_o: [assembly: 100, size: 32, rpi: 10_000, type: :point_to_point],
  config: [assembly: 151, data: <<>>],
  owner: self())
# owner receives: {:eipex_io, ref, :data, binary} | {:eipex_io, ref, :timeout} | {:eipex_io, ref, :closed}
:ok = Eipex.Scanner.IOConnection.set_output(io, <<...>>)   # O→T data to produce
```

### Scanner.Logix (on a session with route_path to the controller)

```elixir
{:ok, plc} = Eipex.Scanner.start_link(host: "10.0.0.5", route_path: [backplane: 0])

{:ok, tags}  = Eipex.Scanner.Logix.tag_list(plc)          # Symbol 0x6B + cached 0x6C templates
{:ok, tag}   = Eipex.Scanner.Logix.read(plc, "MyTag")     # %Eipex.Tag{name, value, type, error: nil}
{:ok, tags}  = Eipex.Scanner.Logix.read(plc, ["A", "B.M[3]", "C"])  # automatic MSP + fragmentation
:ok          = Eipex.Scanner.Logix.write(plc, "MyTag", 42)
```

Rules inherited from pycomm3: per-tag results (`error` in the struct, never an
exception for an individual tag); Logix STRING = `DINT len + SINT[82]` struct;
structural detection of custom strings in templates; system tags (`bit 12`,
`__`, `:`) filtered out of tag_list.

### Adapter

```elixir
{:ok, adapter} = Eipex.Adapter.start_link(
  identity: [vendor_id: 1234, device_type: 0x0C, product_code: 1,
             revision: {1, 0}, serial_number: 42, product_name: "Valiot Edge"],
  assemblies: [
    input:  [instance: 100, size: 32],    # T→O: the adapter produces it
    output: [instance: 150, size: 32],    # O→T: the adapter consumes it
    config: [instance: 151, size: 10]
  ],
  handler: MyApp.EipHandler,              # Eipex.Adapter.Handler behaviour (optional)
  objects: [{0x64, MyApp.CustomObject}],  # extra CIP classes (optional)
  port: 44818, udp_port: 2222)

:ok = Eipex.Adapter.write_assembly(adapter, 100, <<...>>)   # refresh what is produced
{:ok, data} = Eipex.Adapter.read_assembly(adapter, 150)     # last consumed data
```

### Behaviours

```elixir
defmodule Eipex.Adapter.Handler do
  @callback after_assembly_write(instance :: non_neg_integer(), data :: binary(), ctx :: map()) ::
              :ok | {:error, cip_status :: non_neg_integer()}   # includes config rejection
  @callback before_assembly_read(instance :: non_neg_integer(), ctx :: map()) ::
              {:ok, binary()} | :keep                            # refresh production or keep
  @callback run_idle_changed(conn_info :: map(), :run | :idle) :: :ok
  @callback connection_event(conn_info :: map(), :opened | :closed | :timeout) :: :ok
  @callback reset(type :: 0 | 1) :: :ok | {:error, term()}
  # All optional (sensible defaults via __using__)
end

defmodule Eipex.Adapter.Object do
  @callback class_code() :: non_neg_integer()
  @callback handle_service(service :: byte(), instance :: non_neg_integer(),
              path_rest :: [term()], data :: binary(), ctx :: map()) ::
              {:reply, binary()} | {:error, status :: byte(), extended :: [non_neg_integer()]}
end
```

## 5. Data flows

### Scanner reading a tag (explicit)

1. `Logix.read/2` builds the MR request with the codec
   (`4C <words> 91 <len> "MyTag" [pad] 01 00`).
2. If the session has a `route_path`, it is wrapped in Unconnected Send (0x52)
   with a pad byte when the embedded message is odd; if a class 3 connection is
   open, it goes through SendUnitData with a 16-bit sequence count.
3. The session GenServer frames by the encapsulation header `length` (TCP
   stream reassembly), correlates by sender context and replies to the caller.
4. The codec decodes: 16-bit type code → typed Elixir value. Status 0x06
   triggers transparent fragmentation (0x52 with increasing byte offset).

### PLC opens I/O against the adapter (implicit)

1. Forward Open arrives over TCP → `SessionHandler` → `MessageRouter` →
   `Object.ConnectionManager`.
2. Validation order: duplicate triad → ext. 0x0100 · ownership (second
   exclusive owner on the same output assembly) → 0x0106 · missing assemblies →
   0x0129/0x012A/0x012B (invalid config/consuming/producing path) · sizes
   (accounting for the 4B run/idle header and 2B seq count) → 0x0127/0x0128
   with the correct size in the extended status · RPI out of range → 0x0111.
3. Success: starts `Adapter.Connection` (gen_statem, `established` state),
   registers both connection IDs in `Registry`, replies with sockaddr info
   (port 2222; multicast IP from the 239.192.x.x formula when T→O is multicast).
4. Incoming O→T datagrams: `Adapter.UDP` → lookup by connection ID →
   `Connection`: validates the monotonic 32-bit sequence (drops stale/dups),
   strips the 16-bit seq count + 32-bit run/idle, writes to `AssemblyStore`,
   fires `after_assembly_write/3`, resets the watchdog. Run/idle transitions
   fire `run_idle_changed/2`.
5. T→O production: the statem's own RPI timer → `before_assembly_read/2` →
   reads `AssemblyStore` → builds CPF (Sequenced Address 0x8002 + Connected
   Data 0x00B1) → UDP.
6. Watchdog (RPI × 2^multiplier) expires → `timed_out` → cascading close of
   dependent input-only/listen-only connections → `connection_event/2` →
   releases the triad.

Connection types supported by the adapter: **exclusive owner**, **input only**
(O→T heartbeat, no data), **listen only** (requires an existing multicast
producer; dies in cascade with the owner). Multicast master handoff when the
owner closes is deferred to v2 (documented limitation).

### TCP session dies (either role)

Monitors: the `Connection`/`IOConnection` processes tied to the session close,
release Registry entries and notify (`connection_event` / message to the
owner). In the adapter, a crashed `SessionHandler` does not take down the
listener (DynamicSupervisor `one_for_one`, `restart: :temporary`).

## 6. Error handling

- **Network boundary = error boundary.** Malformed input → `{:error, _}` from
  the codec → reply with the encap status (0x0001 invalid command, 0x0003
  malformed CPF, 0x0064 invalid session handle) or CIP status (0x04 path, 0x05
  destination, 0x08 service, 0x13 not enough data, 0x26 path size). Never crash
  on external input.
- **Crash-only for internal bugs:** supervisors restart clean; session/
  connection state is rebuilt from scratch (peers retry per spec).
- **No scanner auto-reconnect:** when the session drops, IOConnections close
  and notify; retrying is the app's decision.
- **Spec timeouts:** 120 s inactivity (adapter, TCP/IP object attribute 13; the
  scanner sends NOP as keepalive), per-connection watchdog, unconnected
  timeout ≥ 10 s.
- **Monotonic sequence numbers** on I/O (never decrement; consumer discards by
  wraparound-aware comparison, `SEQ_GT32` style).

## 7. Testing strategy

No mocks; integration first (organization convention).

1. **Codecs (unit):** real byte vectors documented in
   `docs/research/protocol-byte-layouts.md` (examples from the Rockwell
   1756-PM020 manual, layouts verified against Wireshark/OpENer/EIPScanner) +
   encode/decode roundtrips with StreamData (test-only dependency).
2. **Scanner↔adapter loopback (integration, the flagship test):** both roles in
   the same ExUnit node over `localhost`: session registration → Identity
   attributes → class 1 Forward Open with 10 ms RPI → cyclic exchange → forced
   timeout → cascade → Forward Close. Runs in CI with no external network.
3. **Interop (docker-compose, CI):**
   - Eipex scanner → **OpENer** (reference adapter): explicit + class 1 I/O.
   - **pycomm3** → Eipex adapter: generic messages + Forward Open.
   - Scanner.Logix → **cpppo** (`python -m cpppo.server.enip` simulating tags):
     read/write, fragmentation, MSP. (cpppo supports UCMM only.)
4. **Manual against a real PLC** (ControlLogix/CompactLogix) when hardware is
   available; outside CI.

CI on GitHub Actions with custom `X64`/`ARM64` runners.

## 8. Implementation phases

| Phase | Deliverable | Validation |
|---|---|---|
| 1 | Complete codecs (encap, CPF, EPATH, MR, types, CM, Logix) | byte vectors |
| 2 | Explicit scanner: session, UCMM, `generic_message`, `discover` | cpppo |
| 3 | Explicit adapter: listener, sessions, MessageRouter, standard objects | pycomm3 |
| 4 | Connected class 3 in both roles (FO/FC + SendUnitData) | loopback |
| 5 | Class 1 implicit I/O in both roles (UDP, run/idle, watchdogs, multicast) | loopback + OpENer |
| 6 | Scanner Logix services (tag list, templates/UDTs, frag, MSP) | cpppo |
| 7 | Docs, sample EDS, hex.pm publication | — |

Each phase ends with its tests green before the next one starts. From phase 3
onward the explicit adapter is already usable in production.

## 9. References

- `docs/research/protocol-byte-layouts.md` — complete byte layouts + 14 known
  implementation traps (big-endian sockaddr, EPATH padding, Logix STRING,
  asymmetric run/idle, RPI in µs, etc.). **Read before implementing each phase.**
- `docs/research/opener-architecture.md` — object model, connection lifecycle,
  owner/input-only/listen-only semantics, multicast.
- `docs/research/scanners-elixir-ecosystem.md` — pycomm3/cpppo/libplctag,
  modbux OTP patterns.
- Wireshark `packet-enip.c`/`packet-cip.c` · OpENer · EIPScanner · pycomm3 ·
  Rockwell 1756-PM020 · ODVA PUB00213 (full URLs in the research docs).
