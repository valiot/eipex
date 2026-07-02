# Technical report: Open source EtherNet/IP scanners and the Elixir/Erlang ecosystem

## TOPIC A — Open source EtherNet/IP scanners

### 1. pycomm3: the architectural reference

pycomm3 organizes everything into a three-driver hierarchy: `CIPDriver` (base: EtherNet/IP session, Forward Open/Close, discovery, and generic CIP messaging, useful with any device), `LogixDriver` (extends CIPDriver for ControlLogix/CompactLogix/Micro800: tags, tag list, templates), and `SLCDriver` (legacy SLC500/MicroLogix). It is no longer under active development, but it remains the best-documented open implementation of the scanner role.

**Session and connection.** The cycle is the standard one: `RegisterSession` (stores the session handle), then Forward Open via the Connection Manager with two variants — standard (~500 bytes) or *Large Forward Open* (~4000 bytes) — negotiating the `connection_size` that subsequently governs all fragmentation. A `@with_forward_open` decorator opens the connection on demand with a fallback from large to standard. `close()` performs Forward Close + UnRegister.

**discover().** This is a classmethod that emits *ListIdentity* (0x63) over UDP broadcast to port 44818 from each local IPv4 interface (enumerated with `getaddrinfo`), collects responses in a loop with a 1 s timeout, and parses the Identity object (vendor, product type, revision, serial). If there are no responses, it retries without binding to a specific IP.

**get_tag_list().** It uses the Symbol Object (class 0x6B) with the `Get_Instance_Attribute_List` service (0x55), requesting attributes 1 (name), 2 (symbol type), 3, 5, 6, 8 (array dimensions, 3 DINTs), and 10 (external access, firmware v28+). It iterates by `last_instance`: each response with status `INSUFFICIENT_PACKETS` (0x06) signals to continue from the next instance; `SUCCESS` ends the scan. The 16-bit *symbol type* encodes whether it is atomic or a structure: if bit 15 is set, the low 12 bits are the template's instance id.

**Templates/UDTs (Template Object 0x6C).** A three-step process: (a) `Get_Attribute_List` on 0x6C requesting attributes 4 (definition size), 5 (structure size), 2 (member count), and 1 (structure handle, the CRC that travels in struct reads); (b) the *Read Template* service with offset/length in a loop until the complete buffer is reassembled; (c) parsing: the first `member_count * 20` bytes are member metadata (type info, 16-bit type code, UDINT offset), the rest are null-terminated names. Strings are detected structurally: a template whose members are exactly `LEN` + `DATA` (SINT array) is treated as a fixed-size string (`structure_size - 4`); this covers native STRING and custom strings. Members starting with `__` or `ZZZZZZZZZZ` are hidden (AOI internal members).

**read()/write() and fragmentation.** The API accepts only tag names; the driver estimates the response/request size and decides: if a tag exceeds `connection_size`, it uses *Read Tag Fragmented* (0x52) or *Write Tag Fragmented* (0x53) in a loop with increasing offset, concatenating fragments before decoding. "Small" tags are packed into a *Multiple Service Packet* (0x0A): an accumulator keeps summing sizes and opens a new group when `accumulated_size + next > connection_size`; the final list is `multi_requests + fragmented_requests`. The result is always a `Tag(tag, value, type, error)`: it never raises an exception for an individual tag — a pattern that translates very well to `{:ok, _} | {:error, _}` per tag in Elixir.

**Request/response pipeline.** Each operation is a pair of `RequestPacket`/`ResponsePacket` classes: the request knows how to build itself (`build_request(target_cid, session_id, context, ...)`) and declares its `response_class`; the driver only does send → receive → parse. This design (a packet that builds and decodes itself) maps very well to Elixir modules with pure `encode/1` and `decode/1` plus a transport GenServer.

**generic_message.** This is the programmable "MSG instruction": `service`, `class_code`, `instance`, `attribute`, `request_data`, `data_type` (to decode the response), `connected` (CIP connection vs UCMM), `unconnected_send`, and `route_path` (bool, a string like "1,0", a list, or raw bytes encoded as PADDED_EPATH). It is the escape hatch that prevents every exotic service from requiring a new release — indispensable in the design of an Elixir library.

### 2. API ergonomics: node-ethernet-ip and libplctag

**node-ethernet-ip** (originally by cmseaton42; the maintained fork is ST-node-ethernet-ip) is object-oriented and event-driven: `Controller` (connect, readTag, writeTag, `scan()` with `scan_rate` for polling), `Tag` and `TagGroup` (batches), `"Initialized"`/`"Changed"` events per tag, `ControllerManager` with automatic reconnection, `Browser` for discovery, and even an `IO.Scanner` for implicit I/O. The idea of polling-based subscription with change notification is gold for Elixir: it translates naturally into messages to subscribed processes.

**libplctag** (C, with .NET/Go/Java wrappers) uses the opposite model: an opaque handle + a connection string (`protocol=ab_eip&gateway=10.0.0.1&path=1,0&plc=controllogix&name=MyTag&elem_count=10`), with asynchronous `plc_tag_create/read/write` and typed accessors (`plc_tag_get_int32(tag, offset)`). Less elegant, but it demonstrates that an "everything in the attribute URL" API vastly simplifies declarative configuration (very compatible with Elixir keyword lists).

### 3. cpppo as a testing simulator

cpppo includes a Logix controller simulator: `python -m cpppo.server.enip --print SCADA=INT[1000] TEXT=SSTRING[100]` spins up a "PLC" on port 44818 with those tags (SINT/INT/DINT/REAL/BOOL/STRING/SSTRING types, with optional `Tag@class/instance/attribute` addressing). It supports Read/Write Tag (Fragmented) and Get/Set Attribute, but **only unconnected messaging** — enough to test UCMM, insufficient to test Forward Open. Useful options: `-v` (verbosity), `-a :port`, `--web :12345` (a JSON REST API to inspect/mutate tags live, ideal for integration asserts), and a CLI client (`cpppo.server.enip.client SCADA[1]=99 SCADA[0-10]`) to validate the adapter role if it is ever implemented.

### 4. How they test interoperability

- **pycomm3**: pytest against a real PLC (variable `PLCPATH`), with an L5X export of the test project in the repo; coverage acknowledged as incomplete. It does not use a simulator.
- **libplctag**: maintains `ab_server` (in `src/tests/ab_server`), a single-threaded simulator that "speaks" EIP/CIP for Logix, Micro800, and Omron with basic types (no UDTs), used in CI for regressions. It is one of the few small simulators available.
- **cpppo**: its own simulator+client enables end-to-end testing without hardware.
- Recommended pattern for Elixir: integration tests against cpppo/ab_server in CI (aligned with the preference for integrated tests without mocks) plus binary capture fixtures for the pure codecs.

## TOPIC B — Elixir/Erlang ecosystem

### 1. Existing libraries

Practically a desert. The only real one is **scrub** (github.com/verypossible/scrub, not CargoSense; Apache-2.0, 100% Elixir): an originator/scanner with `open_session`, `read_tag`, `bulk_read_tags`, and access to structure members. Latest release v0.3.0 (March 2022), ~84 commits, 6 stars, **not published on hex.pm** (404). It does not implement a full tag list or rich writes. Searches on hex.pm ("ethernet", "enip", "eip", "cip") return no EtherNet/IP/CIP package; "enip_ex" does not exist; the GitHub `ethernet-ip` topic (67 repos) has zero Elixir repos.

### 2. An EtherNet/IP adapter/server in Elixir/Erlang?

**Confirmed: it does not exist.** Neither on hex.pm nor on GitHub is there an adapter (server role) in Elixir or Erlang; the open adapter stacks are C (OpENer by EIPStackGroup) or the cpppo/libplctag simulators. It is virgin territory.

### 3. OTP inspiration: modbux, opex62541, snapex7

**modbux** (read from the local code) uses plain gen_tcp, no ranch: `Modbux.Tcp.Server` is a GenServer that, in `handle_continue(:setup)`, does `:gen_tcp.listen(port, [:binary, packet: :raw, active: true, reuseaddr: true])` and launches the accept loop as a `Task.async` that, for each `:gen_tcp.accept`, asks a `DynamicSupervisor` (`Server.Supervisor`, one_for_one) for a `Server.Handler` (a GenServer with `restart: :temporary`) and transfers the socket to it with `controlling_process`. The slave's **shared state** is `Modbux.Model.Shared`: an `Agent` with the map `%{slave_id => %{{:hr, addr} => value}}`; each handler runs `Shared.apply(model_pid, cmd)` (an atomic get_and_update) and responds over its socket, with `active: true` mode that notifies the parent process (`{:modbus_tcp, {:slave_request, payload}}`). That listener / DynamicSupervisor-of-handlers / Agent-DB trio is directly reusable for an EtherNet/IP adapter (the Agent would model the tag database/assembly objects). **opex62541** (OPC UA over open62541) and **snapex7** (S7 over Snap7), both by valiot, follow the GenServer-wraps-a-C-port pattern with Client/Server modules; opex62541 is still active (open62541 v1.4.x, 2025). Useful as an API reference, although a pure-Elixir EtherNet/IP stack in the scrub/modbux style is preferable to a C port.

### 4. Recommended OTP building blocks

- **TCP server (port 44818)**: gen_tcp + a custom acceptor (modbux style) works but is handcrafted; **ranch** (Erlang, battle-tested, used by Cowboy) or **ThousandIsland** (pure Elixir, by Mat Trudel, the engine behind Bandit, with a very clean `handler` behaviour API) are better today. For a modern Elixir library, ThousandIsland is the idiomatic choice; plain gen_tcp only if you want zero dependencies like modbux.
- **UDP (discovery/ListIdentity and class 1 implicit I/O)**: `:gen_udp.open(44818, [:binary, active: true, broadcast: true])`; for multicast (implicit I/O uses 239.192.x.x) you join with the `{:add_membership, {group_ip, local_ip}}` option and `:inet`'s `{:multicast_ttl, n}`.
- **Little-endian binaries**: native pattern matching covers all of CIP without dependencies: `<<command::16-little, length::16-little, session::32-little, status::32-little, context::binary-8, options::32-little, data::binary>>` parses the encapsulation header in one line; building it is just as direct. This is Elixir's biggest advantage over Python/C for this protocol.

## URLs consulted

- https://github.com/ottowayi/pycomm3
- https://raw.githubusercontent.com/ottowayi/pycomm3/master/pycomm3/logix_driver.py
- https://raw.githubusercontent.com/ottowayi/pycomm3/master/pycomm3/cip_driver.py
- https://github.com/pjkundert/cpppo
- https://github.com/SerafinTech/ST-node-ethernet-ip
- https://github.com/libplctag/libplctag
- https://github.com/kyle-github/ab_server (via search: libplctag's CI simulator)
- https://github.com/verypossible/scrub
- https://hex.pm/packages?search=ethernet and https://hex.pm/packages?search=enip
- https://github.com/topics/ethernet-ip?l=elixir
- https://github.com/valiot/opex62541
- https://github.com/EIPStackGroup/OpENer (via search)
- Local code: /home/alde/Documents/Elixir/repos/modbux/lib/tcp/server/server.ex, server_supervisor.ex, server_handler.ex and /home/alde/Documents/Elixir/repos/modbux/lib/helpers/shared.ex
