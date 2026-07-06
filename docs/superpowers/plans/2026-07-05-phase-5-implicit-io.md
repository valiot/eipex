# Eipex Phase 5 — Class 1 Implicit I/O Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cyclic class 1 I/O over UDP in both roles: the adapter accepts class 1 Forward Opens against its assemblies (path/size/RPI validation with correct-size extended statuses), consumes O→T data with sequence validation, run/idle tracking and a watchdog, and produces T→O data on the RPI; the scanner opens I/O connections (`Eipex.Scanner.open_io/2` + `Eipex.Scanner.IOConnection` gen_statem), produces O→T with run/idle, consumes T→O with its own watchdog, and notifies an owner process. Validated by loopback (our scanner ↔ our adapter over real UDP) and a real OpENer interop run.

**Scope decisions (documented deviations):**
- **Point-to-point only.** Multicast connection types answer 0x01 + ext 0x0123 (O→T) / 0x0124 (T→O). Multicast allocation/join is deferred (recorded in the deferred-findings doc). OpENer interop works p2p.
- **Exclusive-owner connections only.** Input-only/listen-only (heartbeat) connection points and cascade-close semantics are deferred.
- **UDP ports are exchanged via CPF Sockaddr Info items** (spec-correct, and what makes loopback tests possible): the scanner's FO request carries a T→O sockaddr item (0x8001) advertising its UDP port; the adapter's FO reply carries an O→T sockaddr item (0x8000) advertising its UDP port. IP `{0,0,0,0}` in a sockaddr means "use the TCP session peer address". Real devices default to port 2222 on both sides.
- **No config-data segment** in the connection path (config assembly instance in the path is accepted and validated; config DATA transfer via data segments is deferred).
- Class 1 connections are NOT tied to the TCP session lifetime (per spec): the adapter-side connection dies by watchdog or Forward Close; the ConnectionTable monitors the connection process itself.

**Architecture:** One shared UDP socket per role (`Eipex.Adapter.UDP` GenServer; the scanner's `IOConnection` owns its own socket). Datagrams demux by the 32-bit connection ID in the Sequenced Address item through the ConnectionTable (adapter) / direct socket ownership (scanner). Each connection is a `gen_statem` with two timers: production (RPI) and watchdog (RPI × `timeout_factor(multiplier)`). Sequence rules: the 32-bit address sequence increments per produced packet and consumers drop stale/duplicate values (wraparound-aware compare); the 16-bit class-1 count prefixes the connected data; the run/idle 32-bit header is per-direction configurable (defaults: O→T has it, T→O does not — matching OpENer).

**Tech Stack:** Elixir/OTP only. OpENer built from source in docker for interop.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. No mocks — tests use real UDP/TCP sockets and the real peer role.
- Malformed datagrams are dropped silently (UDP has no error channel); malformed FO fields answer the correct CIP extended statuses (0x0103 transport, 0x0111 RPI, 0x0123/0x0124 connection type, 0x0127/0x0128 size — WITH the correct size as a second extended word, 0x0129/0x012A/0x012B paths).
- RPIs are microseconds on the wire; timers run in milliseconds (`max(1, div(rpi, 1000))`).
- `mix format` before every commit. One CHANGELOG line per commit: `[Type] What changed`, ≤100 chars, appended at the bottom.
- TDD: failing test first. Phases 1-4 suites (204 tests + 3 properties) stay green throughout.

## File Structure

```
eipex/
├── lib/eipex/
│   ├── io.ex                          # Task 1: shared pure helpers (seq compare, framing)
│   ├── adapter/
│   │   ├── handler.ex                 # Task 1: + run_idle_changed/2, connection_event/2
│   │   ├── connection_table.ex        # Task 1: io records (kind, pid, extra monitor)
│   │   ├── message_router.ex          # Task 2: dispatch/3 with cpf extras
│   │   ├── object.ex                  # Task 2: {:reply, data, extra_cpf} return
│   │   ├── session_handler.ex         # Task 2: sockaddr items in/out of rr path
│   │   ├── udp.ex                     # Task 3: shared IO socket (demux + send)
│   │   ├── adapter.ex                 # Task 3: io wiring (io_udp_port, io_sup, config.io)
│   │   ├── config.ex                  # Task 3: + io field
│   │   ├── io_connection.ex           # Task 4: adapter-side gen_statem
│   │   └── object/connection_manager.ex # Task 4: class 1 FO/FC branch
│   ├── scanner.ex                     # Task 5: io_transaction plumbing + open_io API
│   └── scanner/io_connection.ex       # Task 5: scanner-side gen_statem
├── test/eipex/io_test.exs             # Task 1
├── test/eipex/adapter/io_loopback_test.exs      # Tasks 4-6 (raw + scanner loopback)
├── test/eipex/scanner/io_connection_test.exs    # Task 5
├── interop/opener/Dockerfile          # Task 7
├── interop/docker-compose.yml         # Task 7: + opener service
└── test/interop/opener_test.exs       # Task 7
```

**Public API after this phase:**

```elixir
{:ok, io} = Eipex.Scanner.open_io(scanner,
  o_to_t: [assembly: 150, size: 4, rpi: 10_000, run_idle: true],
  t_to_o: [assembly: 100, size: 4, rpi: 10_000, run_idle: false],
  config: [assembly: 151],          # optional
  timeout_multiplier: 2,            # watchdog = rpi * 16
  owner: self())
# owner receives: {:eipex_io, io, :data, binary} | {:eipex_io, io, :run_idle, :run | :idle}
#                 | {:eipex_io, io, :timeout} | {:eipex_io, io, :closed}
:ok = Eipex.Scanner.IOConnection.set_output(io, <<1, 2, 3, 4>>)
:ok = Eipex.Scanner.IOConnection.close(io)   # Forward Close + stop

{:ok, adapter} = Eipex.Adapter.start_link(...,
  io_udp_port: 2222,                # 0 = ephemeral (tests)
  io: [o2t_run_idle: true, t2o_run_idle: false])
{:ok, port} = Eipex.Adapter.io_udp_port(adapter)
```

Adapter handler callbacks now fired by I/O: `after_assembly_write(instance, data, ctx)`
per consumed packet, `before_assembly_read(instance, ctx)` per produced packet,
`run_idle_changed(conn_info, :run | :idle)` on header transitions,
`connection_event(conn_info, :opened | :closed | :timeout)`.

---

### Task 1: Shared I/O helpers + Handler/ConnectionTable extensions

**Files:**
- Create: `lib/eipex/io.ex`
- Modify: `lib/eipex/adapter/handler.ex`, `lib/eipex/adapter/connection_table.ex`
- Test: `test/eipex/io_test.exs`, `test/eipex/adapter/connection_table_test.exs` (append)

**Interfaces:**
- Consumes: `Eipex.CPF` (sequenced address / connected data items).
- Produces:
  - `Eipex.IO.seq_newer?(a, b) :: boolean` — 32-bit wraparound-aware "a is newer than b" (`rem(a - b + 0x1_0000_0000, 0x1_0000_0000)` in `1..0x7FFF_FFFF`).
  - `Eipex.IO.next_seq16(n) :: 0..0xFFFF` — `rem(n + 1, 0x10000)`; `Eipex.IO.next_seq32(n)` — `rem(n + 1, 0x1_0000_0000)`.
  - `Eipex.IO.encode_packet(conn_id, seq32, seq16, run_idle, data) :: binary` — full UDP payload: CPF `[{:sequenced_address, conn_id, seq32}, {:connected_data, <<seq16::16-little, run_idle_header?, data>>}]`; `run_idle :: nil | :run | :idle` (nil = no header; `:run` = `<<1::32-little>>`, `:idle` = `<<0::32-little>>`).
  - `Eipex.IO.decode_packet(datagram, run_idle? :: boolean) :: {:ok, %{conn_id, seq32, seq16, run: nil | :run | :idle, data: binary}} | :error` — tolerant (`:error` = drop).
  - `Eipex.IO.wire_size(data_size, run_idle? :: boolean) :: pos_integer` — `data_size + 2 + (run_idle? && 4 || 0)`.
  - `Eipex.IO.rpi_ms(rpi_us) :: pos_integer` — `max(1, div(rpi_us, 1000))`.
  - Handler behaviour + defaults gain `run_idle_changed(conn_info :: map, :run | :idle) :: :ok` and `connection_event(conn_info :: map, :opened | :closed | :timeout) :: :ok`.
  - ConnectionTable: `register/4`'s `info` map may include `kind: :explicit | :io` (default `:explicit`) and `pid: pid` — when `pid` is present the table ALSO monitors it and cleans that connection on its DOWN (in addition to the session monitor). `lookup_o2t/2` returns the full record (incl. `kind`/`pid`).

- [ ] **Step 1: Write the failing tests**

`test/eipex/io_test.exs`:

```elixir
defmodule Eipex.IOTest do
  use ExUnit.Case, async: true

  alias Eipex.IO

  test "seq_newer? handles monotonic and wraparound cases" do
    assert IO.seq_newer?(2, 1)
    refute IO.seq_newer?(1, 2)
    refute IO.seq_newer?(5, 5)
    # wraparound: 0 is newer than 0xFFFFFFFF
    assert IO.seq_newer?(0, 0xFFFF_FFFF)
    refute IO.seq_newer?(0xFFFF_FFFF, 0)
  end

  test "sequence increments wrap" do
    assert IO.next_seq16(0xFFFF) == 0
    assert IO.next_seq16(5) == 6
    assert IO.next_seq32(0xFFFF_FFFF) == 0
  end

  test "wire_size accounts for seq count and run/idle header" do
    assert IO.wire_size(4, false) == 6
    assert IO.wire_size(4, true) == 10
  end

  test "rpi_ms floors to 1ms" do
    assert IO.rpi_ms(10_000) == 10
    assert IO.rpi_ms(500) == 1
  end

  test "packet round-trips with run/idle header" do
    packet = IO.encode_packet(0xCAFE, 7, 3, :run, <<1, 2, 3, 4>>)

    assert {:ok, %{conn_id: 0xCAFE, seq32: 7, seq16: 3, run: :run, data: <<1, 2, 3, 4>>}} =
             IO.decode_packet(packet, true)

    idle = IO.encode_packet(0xCAFE, 8, 4, :idle, <<0, 0, 0, 0>>)
    assert {:ok, %{run: :idle}} = IO.decode_packet(idle, true)
  end

  test "packet round-trips without run/idle header" do
    packet = IO.encode_packet(0xCAFE, 7, 3, nil, <<9, 9>>)

    assert {:ok, %{conn_id: 0xCAFE, seq32: 7, seq16: 3, run: nil, data: <<9, 9>>}} =
             IO.decode_packet(packet, false)
  end

  test "malformed datagrams decode to :error, never raise" do
    assert :error = IO.decode_packet(<<1, 2, 3>>, true)
    assert :error = IO.decode_packet(:binary.copy(<<0>>, 20), false)
    # run_idle expected but payload too short for the header
    short = IO.encode_packet(1, 1, 1, nil, <<1>>)
    assert :error = IO.decode_packet(short, true)
  end
end
```

Append to `test/eipex/adapter/connection_table_test.exs`:

```elixir
  test "io records carry kind and pid, and die with the pid" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    statem =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    triad = {9, 0x004D, 0xDEAD_0009}

    assert {:ok, o2t} =
             ConnectionTable.register(table, triad,
               %{t2o_connection_id: 42, kind: :io, pid: statem}, self())

    assert {:ok, %{kind: :io, pid: ^statem}} = ConnectionTable.lookup_o2t(table, o2t)

    send(statem, :stop)
    Process.sleep(50)
    assert :error = ConnectionTable.lookup_o2t(table, o2t)
  end

  test "explicit records default kind" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    {:ok, o2t} =
      ConnectionTable.register(table, {1, 1, 1}, %{t2o_connection_id: 1}, self())

    assert {:ok, %{kind: :explicit}} = ConnectionTable.lookup_o2t(table, o2t)
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/io_test.exs test/eipex/adapter/connection_table_test.exs`
Expected: FAIL — `Eipex.IO` undefined; table tests fail on `kind`.

- [ ] **Step 3: Implement**

`lib/eipex/io.ex` — NAMING NOTE: `alias Eipex.IO` shadows Elixir's `IO` module
inside any module that aliases it; do not use `IO.puts`/`IO.inspect` in those
modules (use `Kernel.inspect` + Logger if needed):

```elixir
defmodule Eipex.IO do
  @moduledoc """
  Pure helpers for class 1 implicit I/O: sequence arithmetic with wraparound,
  RPI conversion, and the UDP packet framing (CPF Sequenced Address +
  Connected Data with 16-bit sequence count and optional 32-bit run/idle
  header).
  """

  alias Eipex.CPF

  @mod32 0x1_0000_0000

  @spec seq_newer?(non_neg_integer(), non_neg_integer()) :: boolean()
  def seq_newer?(a, b) do
    diff = rem(a - b + @mod32, @mod32)
    diff in 1..0x7FFF_FFFF
  end

  @spec next_seq16(non_neg_integer()) :: 0..0xFFFF
  def next_seq16(n), do: rem(n + 1, 0x10000)

  @spec next_seq32(non_neg_integer()) :: non_neg_integer()
  def next_seq32(n), do: rem(n + 1, @mod32)

  @spec wire_size(non_neg_integer(), boolean()) :: pos_integer()
  def wire_size(data_size, run_idle?), do: data_size + 2 + if(run_idle?, do: 4, else: 0)

  @spec rpi_ms(pos_integer()) :: pos_integer()
  def rpi_ms(rpi_us), do: max(1, div(rpi_us, 1000))

  @spec encode_packet(non_neg_integer(), non_neg_integer(), non_neg_integer(),
          nil | :run | :idle, binary()) :: binary()
  def encode_packet(conn_id, seq32, seq16, run_idle, data) do
    header =
      case run_idle do
        nil -> <<>>
        :run -> <<1::32-little>>
        :idle -> <<0::32-little>>
      end

    CPF.encode([
      {:sequenced_address, conn_id, seq32},
      {:connected_data, <<seq16::16-little, header::binary, data::binary>>}
    ])
  end

  @spec decode_packet(binary(), boolean()) ::
          {:ok, %{conn_id: non_neg_integer(), seq32: non_neg_integer(),
                  seq16: non_neg_integer(), run: nil | :run | :idle, data: binary()}}
          | :error
  def decode_packet(datagram, run_idle?) do
    with {:ok, items} <- CPF.decode(datagram),
         [{:sequenced_address, conn_id, seq32}] <-
           (for {:sequenced_address, _, _} = i <- items, do: i),
         [{:connected_data, payload}] <-
           (for {:connected_data, _} = i <- items, do: i),
         {:ok, seq16, run, data} <- split_payload(payload, run_idle?) do
      {:ok, %{conn_id: conn_id, seq32: seq32, seq16: seq16, run: run, data: data}}
    else
      _ -> :error
    end
  end

  defp split_payload(<<seq16::16-little, header::32-little, data::binary>>, true) do
    run = if Bitwise.band(header, 1) == 1, do: :run, else: :idle
    {:ok, seq16, run, data}
  end

  defp split_payload(<<seq16::16-little, data::binary>>, false) do
    {:ok, seq16, nil, data}
  end

  defp split_payload(_, _), do: :error
end
```

Handler additions (behaviour + `__using__` defaults + defoverridable list):

```elixir
  @callback run_idle_changed(conn_info :: map(), :run | :idle) :: :ok
  @callback connection_event(conn_info :: map(), :opened | :closed | :timeout) :: :ok
  # defaults inside __using__:
      def run_idle_changed(_conn_info, _mode), do: :ok
      def connection_event(_conn_info, _event), do: :ok
  # add run_idle_changed: 2, connection_event: 2 to defoverridable
```

ConnectionTable changes:
- `register` merges `kind: :explicit` default into the record (`Map.put_new(info, :kind, :explicit)`).
- When `info[:pid]` is set, also `Process.monitor(info.pid)` (same `put_new_lazy` monitors-map pattern keyed by that pid).
- The DOWN handler's split must match records where `record.session == pid OR record[:pid] == pid`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/io_test.exs test/eipex/adapter/connection_table_test.exs`
Expected: PASS. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Implicit I/O helpers, handler I/O callbacks and connection-table I/O records`

```bash
mix format && git add -A && git commit -m "feat: implicit io foundations"
```

---

### Task 2: CPF extras through dispatch (sockaddr in/out)

**Files:**
- Modify: `lib/eipex/adapter/message_router.ex`, `lib/eipex/adapter/object.ex`, `lib/eipex/adapter/session_handler.ex`
- Test: `test/eipex/adapter/message_router_test.exs`, `test/eipex/adapter/session_handler_test.exs` (append)

**Interfaces:**
- Consumes: existing dispatch/session plumbing.
- Produces:
  - `Object` behaviour gains a fourth return shape: `{:reply, data, extra_cpf :: [Eipex.CPF.item()]}` — extra CPF items to append to the encapsulation reply (used for sockaddr items in class 1 FO replies).
  - `MessageRouter.dispatch(config, request, extra :: map) :: {response :: binary, extra_cpf :: [item]}` (new 3-arity). `extra` is merged into ctx (adds `cpf_items: [item]` from the request's CPF and anything else the session provides). The existing `dispatch/2` remains and returns ONLY the response binary (delegates with `extra: %{}` and drops extras) — all Phase 3-4 callers/tests unchanged.
  - `SessionHandler`'s SendRRData path: passes the request's full decoded CPF items into `dispatch/3` as `%{cpf_items: items}` and appends returned `extra_cpf` to the reply CPF (after the two standard items).
  - `{:raw, _}` (Unconnected Send) keeps extras: the CM object's UCMM recursion uses `dispatch/2` semantics (no sockaddr inside embedded requests) — unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `test/eipex/adapter/message_router_test.exs`:

```elixir
  defmodule ExtraCpfObject do
    @behaviour Eipex.Adapter.Object

    def handle_service(0x0E, 1, _path, _data, ctx) do
      # echoes how many CPF items the session handed us, and returns a sockaddr
      count = length(Map.get(ctx, :cpf_items, []))

      {:reply, <<count>>,
       [{:sockaddr_o2t, %{ip: {127, 0, 0, 1}, port: 4321}}]}
    end
  end

  test "dispatch/3 threads cpf items in and extra cpf items out" do
    cfg = config()
    cfg = %{cfg | objects: Map.put(cfg.objects, 0x65, ExtraCpfObject)}

    request = MR.encode_request(0x0E, class: 0x65, instance: 1)

    {response, extra} =
      MessageRouter.dispatch(cfg, request, %{cpf_items: [:null_address, {:unconnected_data, <<>>}]})

    assert {:ok, %{status_name: :success, data: <<2>>}} = MR.decode_response(response)
    assert extra == [{:sockaddr_o2t, %{ip: {127, 0, 0, 1}, port: 4321}}]
  end

  test "dispatch/2 keeps the old binary contract" do
    cfg = config()
    cfg = %{cfg | objects: Map.put(cfg.objects, 0x65, ExtraCpfObject)}

    request = MR.encode_request(0x0E, class: 0x65, instance: 1)
    response = MessageRouter.dispatch(cfg, request)

    assert is_binary(response)
    assert {:ok, %{data: <<0>>}} = MR.decode_response(response)
  end
```

Append to `test/eipex/adapter/session_handler_test.exs` (uses the raw-client helpers):

```elixir
  defmodule SockaddrObject do
    @behaviour Eipex.Adapter.Object

    def handle_service(0x0E, 1, _path, _data, _ctx) do
      {:reply, <<>>, [{:sockaddr_o2t, %{ip: {0, 0, 0, 0}, port: 2222}}]}
    end
  end

  test "extra cpf items from objects ride the send_rr_data reply" do
    {_pid, port} = start_adapter(objects: [{0x66, SockaddrObject}])
    socket = connect(port)
    handle = register(socket)

    mr = Eipex.CIP.MessageRouter.encode_request(0x0E, class: 0x66, instance: 1)
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}])
    send_frame(socket, Encap.send_rr_data(handle, cpf))

    reply = recv_frame(socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)

    assert [{:sockaddr_o2t, %{port: 2222}}] =
             for {:sockaddr_o2t, _} = i <- items, do: i
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/message_router_test.exs test/eipex/adapter/session_handler_test.exs`
Expected: FAIL — `dispatch/3` undefined; 3-element reply tuple unhandled.

- [ ] **Step 3: Implement**

`MessageRouter`: rename the internal pipeline to carry extras.

```elixir
  @spec dispatch(Config.t(), binary()) :: binary()
  def dispatch(%Config{} = config, request) do
    {response, _extra} = dispatch(config, request, %{})
    response
  end

  @spec dispatch(Config.t(), binary(), map()) :: {binary(), [Eipex.CPF.item()]}
  def dispatch(%Config{} = config, request, extra) do
    case MR.decode_request(request) do
      {:ok, %{service: service, path: path, data: data}} ->
        route(config, service, path, data, extra)

      {:error, _} ->
        {MR.encode_response(0x00, 0x13), []}
    end
  end
```

`route/5` and `invoke/7` thread `extra` and wrap all existing returns as
`{binary, []}`; the ctx becomes:

```elixir
        ctx =
          Map.merge(
            %{config: config, store: config.store, handler: config.handler,
              session: self(), connections: config.connections},
            extra
          )
```

and the object-result case gains:

```elixir
            {:reply, reply_data, extra_cpf} ->
              {MR.encode_response(service, 0x00, data: reply_data), extra_cpf}
```

(`{:raw, response}` → `{response, []}`; `{:reply, data}` → `{..., []}`;
`{:error, ...}` → `{..., []}`; the rescue → `{MR.encode_response(service, 0x1F), []}`.)

`Object` behaviour: extend the callback typespec/doc with the new return shape.

`SessionHandler` SendRRData success branch becomes:

```elixir
          {:ok, mr_request, items} ->
            {response, extra_cpf} =
              MessageRouter.dispatch(state.config, mr_request, %{cpf_items: items})

            cpf =
              CPF.encode(
                [:null_address, {:unconnected_data, response}] ++ extra_cpf
              )
            ...
```

(`rr_payload/1` now returns `{:ok, mr, items}` — it already decodes the items;
keep the malformed branch as-is.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/`
Expected: PASS (3 new + all existing adapter tests — the dispatch/2 wrapper keeps
Phase 3-4 tests untouched). Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] CPF extras threaded through adapter dispatch for I/O sockaddr exchange`

```bash
mix format && git add -A && git commit -m "feat: cpf extras through dispatch"
```

---

### Task 3: Adapter UDP socket + wiring

**Files:**
- Create: `lib/eipex/adapter/udp.ex`
- Modify: `lib/eipex/adapter/adapter.ex`, `lib/eipex/adapter/config.ex`
- Test: `test/eipex/adapter/udp_test.exs`

**Interfaces:**
- Consumes: `Eipex.IO.decode_packet? NO — demux only needs the conn id`: the UDP process peeks the Sequenced Address item via `CPF.decode` and forwards the RAW parsed pieces; full framing decode happens in the connection statem (which knows its run/idle config).
- Produces:
  - `Eipex.Adapter.UDP.start_link(%{port: n, connections: table}) :: {:ok, pid}` — binds `[:binary, active: true, reuseaddr: true]`.
  - Demux: on datagram → `CPF.decode` → `{:sequenced_address, conn_id, _}` present → `ConnectionTable.lookup_o2t(table, conn_id)` → record with `kind: :io` and `pid` → `send(pid, {:io_datagram, datagram, {ip, port}})`. Anything else: drop silently. Catch-all `handle_info`.
  - `UDP.port(pid) :: {:ok, port}`; `UDP.send(pid, ip, port, packet) :: :ok` (cast — the socket owner performs the send).
  - `Config` gains `io: %{udp: pid | nil, o2t_run_idle: boolean, t2o_run_idle: boolean}`.
  - `Adapter` opts: `io_udp_port` (default 2222; 0 ephemeral), `io: [o2t_run_idle: true, t2o_run_idle: false]`; starts `Adapter.UDP` and an `io_sup` DynamicSupervisor in init (linked, like the rest); public `Eipex.Adapter.io_udp_port(adapter)`. The io_sup pid rides `config.io` as `sup: pid`.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/udp_test.exs`:

```elixir
defmodule Eipex.Adapter.UDPTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{ConnectionTable, UDP}

  defp start_pair do
    {:ok, table} = ConnectionTable.start_link(max: 8)
    {:ok, udp} = UDP.start_link(%{port: 0, connections: table})
    {:ok, port} = UDP.port(udp)
    {table, udp, port}
  end

  test "routes datagrams to the registered io connection process" do
    {table, _udp, port} = start_pair()

    {:ok, o2t} =
      ConnectionTable.register(table, {1, 1, 1},
        %{t2o_connection_id: 9, kind: :io, pid: self()}, self())

    packet = Eipex.IO.encode_packet(o2t, 1, 1, :run, <<1, 2, 3, 4>>)
    {:ok, sender} = :gen_udp.open(0, [:binary])
    :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, packet)

    assert_receive {:io_datagram, ^packet, {_ip, _sender_port}}, 500
    :gen_udp.close(sender)
  end

  test "unknown connection ids and garbage are dropped silently" do
    {table, udp, port} = start_pair()

    {:ok, sender} = :gen_udp.open(0, [:binary])
    :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, Eipex.IO.encode_packet(999, 1, 1, nil, <<1>>))
    :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, <<0xDE, 0xAD>>)

    refute_receive {:io_datagram, _, _}, 200
    assert Process.alive?(udp)
    _ = table
    :gen_udp.close(sender)
  end

  test "explicit-kind connections are not io-routable" do
    {table, _udp, port} = start_pair()

    {:ok, o2t} =
      ConnectionTable.register(table, {2, 1, 1}, %{t2o_connection_id: 9}, self())

    {:ok, sender} = :gen_udp.open(0, [:binary])
    :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, Eipex.IO.encode_packet(o2t, 1, 1, nil, <<1>>))

    refute_receive {:io_datagram, _, _}, 200
    :gen_udp.close(sender)
  end

  test "send/4 transmits from the shared socket" do
    {_table, udp, _port} = start_pair()

    {:ok, receiver} = :gen_udp.open(0, [:binary, active: true])
    {:ok, rport} = :inet.port(receiver)

    :ok = UDP.send(udp, {127, 0, 0, 1}, rport, <<7, 7, 7>>)
    assert_receive {:udp, ^receiver, _, _, <<7, 7, 7>>}, 500
    :gen_udp.close(receiver)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/udp_test.exs`
Expected: FAIL — `UDP` undefined.

- [ ] **Step 3: Implement**

`lib/eipex/adapter/udp.ex`:

```elixir
defmodule Eipex.Adapter.UDP do
  @moduledoc """
  The adapter's shared class 1 I/O socket (default UDP 2222). Inbound
  datagrams are demultiplexed by the 32-bit connection ID in the Sequenced
  Address item and forwarded to the owning connection process; everything
  unroutable is dropped (UDP has no error channel). Outbound sends are
  serialized through this process (the socket owner).
  """

  use GenServer

  alias Eipex.Adapter.ConnectionTable
  alias Eipex.CPF

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def port(server), do: GenServer.call(server, :port)

  @spec send(GenServer.server(), :inet.ip4_address(), :inet.port_number(), binary()) :: :ok
  def send(server, ip, port, packet), do: GenServer.cast(server, {:send, ip, port, packet})

  @impl true
  def init(%{port: port, connections: connections}) do
    case :gen_udp.open(port, [:binary, active: true, reuseaddr: true]) do
      {:ok, socket} -> {:ok, %{socket: socket, connections: connections}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, :inet.port(state.socket), state}

  @impl true
  def handle_cast({:send, ip, port, packet}, state) do
    _ = :gen_udp.send(state.socket, ip, port, packet)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, socket, ip, port, datagram}, %{socket: socket} = state) do
    with {:ok, items} <- CPF.decode(datagram),
         [{:sequenced_address, conn_id, _seq}] <-
           (for {:sequenced_address, _, _} = i <- items, do: i),
         {:ok, %{kind: :io, pid: pid}} <-
           ConnectionTable.lookup_o2t(state.connections, conn_id) do
      Kernel.send(pid, {:io_datagram, datagram, {ip, port}})
    else
      _ -> :ok
    end

    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}
end
```

Adapter wiring in `init/1` (after the ConnectionTable):

```elixir
         {:ok, io_udp} <-
           Eipex.Adapter.UDP.start_link(%{
             port: Keyword.get(opts, :io_udp_port, 2222),
             connections: connections
           }),
         {:ok, io_sup} <- DynamicSupervisor.start_link(strategy: :one_for_one),
```

`config.io`:

```elixir
        io_opts = Keyword.get(opts, :io, [])

        io = %{
          udp: io_udp,
          sup: io_sup,
          o2t_run_idle: Keyword.get(io_opts, :o2t_run_idle, true),
          t2o_run_idle: Keyword.get(io_opts, :t2o_run_idle, false)
        }
```

(`Config` defstruct gains `io: nil`; set `io: io` when building the config.)
Public API + handle_call:

```elixir
  @spec io_udp_port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def io_udp_port(server), do: GenServer.call(server, :io_udp_port)

  def handle_call(:io_udp_port, _from, state) do
    {:reply, Eipex.Adapter.UDP.port(state.config.io.udp), state}
  end
```

NOTE: binding UDP 2222 by default can collide when several adapters run on one
host — tests always pass `io_udp_port: 0`. Update the adapter tests that call
`start_adapter` if any now collide (they all use `port: 0`; add
`io_udp_port: 0` to the shared helpers in adapter/session/loopback/discovery
test files).

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/`
Expected: PASS (4 new + existing; helpers updated with `io_udp_port: 0`). Full
`mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter shared I/O UDP socket with connection-id demux`

```bash
mix format && git add -A && git commit -m "feat: adapter io udp socket"
```

---

### Task 4: Adapter I/O connections (gen_statem + class 1 Forward Open)

**Files:**
- Create: `lib/eipex/adapter/io_connection.ex`
- Modify: `lib/eipex/adapter/object/connection_manager.ex` (class 1 branch, FC io close), `lib/eipex/adapter/session_handler.ex` (peer_ip into dispatch extras)
- Test: `test/eipex/adapter/io_loopback_test.exs` (raw gen_tcp session + raw gen_udp peer)

**Interfaces:**
- Consumes: Tasks 1-3 (IO helpers, table io records, UDP socket, cpf extras), `AssemblyStore`, `Handler`.
- Produces:
  - `Eipex.Adapter.IoConnection` (`:gen_statem`, `restart: :temporary`):
    - `start_link(args)` starts in a `:waiting` state; `activate(pid, o2t_id, peer)` moves to `:established` (arming both timers and firing `connection_event(conn_info, :opened)`).
    - Consumption (`{:io_datagram, datagram, from}` info): `IO.decode_packet(datagram, o2t_run_idle)`; drop unless `conn_id == o2t_id`, `IO.seq_newer?(seq32, last)`, `byte_size(data) == o2t_size`. On accept: `AssemblyStore.write(store, o2t_assembly, data)`, `handler.after_assembly_write/3`, run/idle transition → `handler.run_idle_changed/2` (initial state `:idle`; only fires on CHANGE), reset watchdog timer.
    - Production (`{:timeout, :produce}` generic timer every `t2o_rpi_ms`): `handler.before_assembly_read/2` refresh (same semantics as explicit reads), `AssemblyStore.read(t2o_assembly)`, increment seq16/seq32 (producer-side counters), `Eipex.IO.encode_packet(t2o_id, seq32, seq16, t2o_run_idle && :run || nil, data)`, `UDP.send(udp, peer_ip, peer_port, packet)`, re-arm.
    - Watchdog (`{:timeout, :watchdog}` after `o2t_rpi_ms * timeout_factor(multiplier)`): `connection_event(conn_info, :timeout)`, `ConnectionTable.unregister(table, triad)`, stop `:normal`.
    - `:close` info (sent by the CM object on Forward Close): `connection_event(conn_info, :closed)`, stop `:normal` (the CM already unregistered).
  - CM object class dispatch: `fo.transport.class` → `3` existing explicit flow · `1` new IO flow · other → `{:error, 0x01, [0x0103]}`. IO flow validation order:
    1. connection types: `o2t_params.type != :point_to_point` → `[0x0123]`; t2o → `[0x0124]`
    2. RPIs in `1_000..10_000_000` µs both → else `[0x0111]`
    3. path (ports stripped): `[{:class, 0x04} | rest]` where `rest` is optional `{:instance, cfg}` then EXACTLY `[{:connection_point, o2t_asm}, {:connection_point, t2o_asm}]` → else `[0x0315]`
    4. assembly kinds via `AssemblyStore.info/2`: o2t point must be `:output` → else `[0x012A]`; t2o point `:input` → `[0x012B]`; cfg (when present) `:config` → `[0x0129]`
    5. sizes: `fo.o2t_params.size == IO.wire_size(output_size, config.io.o2t_run_idle)` → else `{:error, 0x01, [0x0127, correct_size]}`; t2o likewise `[0x0128, correct_size]`
    6. start statem under `config.io.sup` → register `%{t2o_connection_id, kind: :io, pid: statem}` (duplicate → `[0x0100]` + stop statem; capacity → `[0x0113]` + stop statem) → `activate(statem, o2t_id, peer)`
    - peer resolution: `{:sockaddr_t2o, %{ip, port}}` in `ctx.cpf_items` (ip `{0,0,0,0}` → `ctx.peer_ip`); item absent → `{ctx.peer_ip, 2222}`.
    - reply: `{:reply, encode_forward_open_reply(...), [{:sockaddr_o2t, %{ip: {0,0,0,0}, port: adapter_io_udp_port}}]}` (port via `UDP.port(config.io.udp)`).
  - FC branch: after successful unregister, `if record.kind == :io, do: send(record.pid, :close)`.
  - SessionHandler: the SendRRData dispatch extras gain `peer_ip` (from `:inet.peername(state.socket)`, captured once at activate).

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/io_loopback_test.exs` — raw peers; the FO helper builds class 1
Forward Opens with a sockaddr item:

```elixir
defmodule Eipex.Adapter.IoLoopbackTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  defmodule IoHandler do
    use Eipex.Adapter.Handler

    def after_assembly_write(instance, data, _ctx) do
      send(:io_loopback_test, {:written, instance, data})
      :ok
    end

    def run_idle_changed(_info, mode) do
      send(:io_loopback_test, {:run_idle, mode})
      :ok
    end

    def connection_event(_info, event) do
      send(:io_loopback_test, {:conn_event, event})
      :ok
    end
  end

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  setup do
    Process.register(self(), :io_loopback_test)

    {:ok, adapter} =
      Eipex.Adapter.start_link(
        identity: @identity,
        handler: IoHandler,
        assemblies: [input: [instance: 100, size: 4],
                     output: [instance: 150, size: 4],
                     config: [instance: 151, size: 2]],
        port: 0, io_udp_port: 0)

    {:ok, tcp_port} = Eipex.Adapter.port(adapter)
    {:ok, io_port} = Eipex.Adapter.io_udp_port(adapter)

    socket = connect(tcp_port)
    handle = register(socket)

    {:ok, udp} = :gen_udp.open(0, [:binary, active: true])
    {:ok, my_udp_port} = :inet.port(udp)

    on_exit(fn -> Process.unregister(:io_loopback_test) end)

    %{adapter: adapter, socket: socket, handle: handle, udp: udp,
      my_udp_port: my_udp_port, io_port: io_port}
  end

  defp connect(port) do
    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, packet: :raw, active: false])

    socket
  end

  defp send_frame(socket, frame), do: :ok = :gen_tcp.send(socket, Encap.encode(frame))

  defp recv_frame(socket, buffer \\ <<>>) do
    {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)

    case Encap.decode(buffer <> data) do
      {:ok, frame, _rest} -> frame
      :partial -> recv_frame(socket, buffer <> data)
    end
  end

  defp register(socket) do
    send_frame(socket, Encap.register_session())
    %Encap{session_handle: handle} = recv_frame(socket)
    handle
  end

  defp io_forward_open(ctx, overrides \\ []) do
    o2t_size = Keyword.get(overrides, :o2t_size, 10)   # 4 data + 2 seq + 4 run/idle
    t2o_size = Keyword.get(overrides, :t2o_size, 6)    # 4 data + 2 seq
    rpi = Keyword.get(overrides, :rpi, 20_000)
    serial = Keyword.get(overrides, :serial, 1)
    conn_type = Keyword.get(overrides, :conn_type, :point_to_point)

    path =
      Keyword.get(overrides, :path,
        Path.encode([{:class, 0x04}, {:instance, 151},
                     {:connection_point, 150}, {:connection_point, 100}]))

    fo = %CM.ForwardOpen{
      priority_time_tick: 0x0A, timeout_ticks: 10,
      o2t_connection_id: 0, t2o_connection_id: 0x5150_0000 + serial,
      connection_serial: serial, originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      timeout_multiplier: Keyword.get(overrides, :multiplier, 1),
      o2t_rpi: rpi,
      o2t_params: %{owner: :exclusive, type: conn_type, priority: :low,
                    size_type: :fixed, size: o2t_size},
      t2o_rpi: rpi,
      t2o_params: %{owner: :exclusive, type: conn_type, priority: :low,
                    size_type: :fixed, size: t2o_size},
      transport: %{direction: :server, trigger: :cyclic, class: 1},
      connection_path: path
    }

    cpf =
      CPF.encode([
        :null_address,
        {:unconnected_data, CM.encode_forward_open(fo, :standard)},
        {:sockaddr_t2o, %{ip: {0, 0, 0, 0}, port: ctx.my_udp_port}}
      ])

    send_frame(ctx.socket, Encap.send_rr_data(ctx.handle, cpf))
    reply = recv_frame(ctx.socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)
    [{:unconnected_data, mr}] = for {:unconnected_data, _} = i <- items, do: i
    {:ok, response} = MR.decode_response(mr)
    sockaddrs = for {:sockaddr_o2t, sa} <- items, do: sa
    {fo, response, sockaddrs}
  end

  test "forward open succeeds, adapter produces on the RPI", ctx do
    {fo, response, [%{port: adapter_io_port}]} = io_forward_open(ctx)
    assert response.status_name == :success
    assert adapter_io_port == ctx.io_port
    assert_receive {:conn_event, :opened}, 500

    {:ok, reply} = CM.decode_forward_open_reply(response.data)
    assert reply.t2o_connection_id == fo.t2o_connection_id

    # production arrives on our UDP socket: t2o id, growing sequences, zeroed data
    assert_receive {:udp, _, _, _, datagram}, 500
    assert {:ok, %{conn_id: conn_id, data: <<0, 0, 0, 0>>, run: nil, seq32: s1}} =
             Eipex.IO.decode_packet(datagram, false)

    assert conn_id == fo.t2o_connection_id

    assert_receive {:udp, _, _, _, datagram2}, 500
    {:ok, %{seq32: s2}} = Eipex.IO.decode_packet(datagram2, false)
    assert Eipex.IO.seq_newer?(s2, s1)

    # refresh the produced data through the public API
    :ok = Eipex.Adapter.write_assembly(ctx.adapter, 100, <<9, 8, 7, 6>>)
    assert_eventually_produces(<<9, 8, 7, 6>>)
  end

  defp assert_eventually_produces(expected, tries \\ 20) do
    assert tries > 0, "never produced #{inspect(expected)}"

    receive do
      {:udp, _, _, _, datagram} ->
        case Eipex.IO.decode_packet(datagram, false) do
          {:ok, %{data: ^expected}} -> :ok
          _ -> assert_eventually_produces(expected, tries - 1)
        end
    after
      500 -> flunk("no production within 500ms")
    end
  end

end
```

IMPORTANT: make `io_forward_open/2` return `{fo, response, fo_reply_or_nil, sockaddrs}`
where `fo_reply_or_nil` is the decoded `%ForwardOpenReply{}` on success (`nil`
otherwise) — the consumption tests need the adapter-assigned `o2t_connection_id`.
Write these 9 tests (test 1's body is shown above; write 2-9 with the same
helpers, each assertion below is exact):

1. **production** (as above, adjusted to the 4-tuple helper).
2. **consumption**: send `Eipex.IO.encode_packet(fo_reply.o2t_connection_id, 1, 1, :run, <<1, 2, 3, 4>>)`
   to `{127,0,0,1}, ctx.io_port` from `ctx.udp` → `assert_receive {:written, 150, <<1,2,3,4>>}`
   and `assert_receive {:run_idle, :run}` → `Eipex.Adapter.read_assembly(adapter, 150) == {:ok, <<1,2,3,4>>}`.
3. **stale sequences dropped**: send seq32=5 data A (accepted), then seq32=3 data B →
   only one `{:written, ...}`; store keeps A. Then seq32=6 accepted.
4. **run→idle transition**: send `:run` packet then `:idle` packet (seq32 7, 8) →
   `{:run_idle, :run}` then `{:run_idle, :idle}` exactly once each.
5. **watchdog**: rpi 20ms, multiplier 0 (factor 4 → 80ms): stop sending after one
   packet → `assert_receive {:conn_event, :timeout}, 1_000` → the triad frees
   (same-serial FO now succeeds) and production stops (flush mailbox, `refute_receive {:udp, ...}, 200`).
6. **forward close**: successful FC (reuse the Phase 4 FC encode over UCMM) →
   `{:conn_event, :closed}` → production stops.
7. **size mismatch answers 0x0127/0x0128 with the correct size**:
   `io_forward_open(ctx, o2t_size: 99)` → `extended == [0x0127, 10]`;
   `t2o_size: 99` → `extended == [0x0128, 6]`.
8. **multicast refused**: `conn_type: :multicast` → `extended == [0x0123]`.
9. **path/kind validation**: swapped connection points
   (`path: Path.encode([{:class, 4}, {:instance, 151}, {:connection_point, 100}, {:connection_point, 150}])`
   → o2t point is an `:input` assembly → `[0x012A]`); RPI 100 → `[0x0111]`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/io_loopback_test.exs`
Expected: FAIL — class 1 FOs currently answer 0x0103 (Phase 4 refusal).

- [ ] **Step 3: Implement**

`lib/eipex/adapter/io_connection.ex`:

```elixir
defmodule Eipex.Adapter.IoConnection do
  @moduledoc """
  One class 1 (cyclic) I/O connection on the adapter side. Consumes O->T
  datagrams (sequence-validated, run/idle tracked, watchdog-guarded) and
  produces T->O datagrams on the RPI from the input assembly. Point-to-point,
  exclusive owner. Dies on watchdog timeout or Forward Close; the
  ConnectionTable monitors this process, so death always releases the triad.
  """

  @behaviour :gen_statem

  alias Eipex.Adapter.{AssemblyStore, ConnectionTable, UDP}
  alias Eipex.IO

  def child_spec(args) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [args]}, restart: :temporary}
  end

  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  def activate(pid, o2t_id, peer), do: :gen_statem.cast(pid, {:activate, o2t_id, peer})

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(args) do
    {:ok, :waiting, Map.merge(args, %{o2t_id: nil, peer: nil, last_seq32: nil,
                                      run_state: :idle, prod_seq32: 0, prod_seq16: 0})}
  end

  @impl true
  def handle_event(:cast, {:activate, o2t_id, peer}, :waiting, data) do
    data = %{data | o2t_id: o2t_id, peer: peer}
    data.handler.connection_event(conn_info(data), :opened)

    {:next_state, :established, data,
     [{{:timeout, :produce}, data.t2o_rpi_ms, :produce},
      {{:timeout, :watchdog}, data.watchdog_ms, :watchdog}]}
  end

  def handle_event(:info, {:io_datagram, datagram, _from}, :established, data) do
    case IO.decode_packet(datagram, data.o2t_run_idle) do
      {:ok, %{conn_id: conn_id, seq32: seq32, run: run, data: payload}}
      when conn_id == data.o2t_id ->
        cond do
          not is_nil(data.last_seq32) and not IO.seq_newer?(seq32, data.last_seq32) ->
            {:keep_state, data}

          byte_size(payload) != data.o2t_size ->
            {:keep_state, data}

          true ->
            :ok = AssemblyStore.write(data.store, data.o2t_assembly, payload)
            _ = data.handler.after_assembly_write(data.o2t_assembly, payload, %{})
            data = track_run_idle(data, run)

            {:keep_state, %{data | last_seq32: seq32},
             [{{:timeout, :watchdog}, data.watchdog_ms, :watchdog}]}
        end

      _ ->
        {:keep_state, data}
    end
  end

  def handle_event({:timeout, :produce}, :produce, :established, data) do
    payload =
      case data.handler.before_assembly_read(data.t2o_assembly, %{}) do
        {:ok, fresh} ->
          case AssemblyStore.write(data.store, data.t2o_assembly, fresh) do
            :ok -> fresh
            {:error, _} -> read_stored(data)
          end

        :keep ->
          read_stored(data)
      end

    seq32 = IO.next_seq32(data.prod_seq32)
    seq16 = IO.next_seq16(data.prod_seq16)
    run_idle = if data.t2o_run_idle, do: :run, else: nil
    packet = IO.encode_packet(data.t2o_id, seq32, seq16, run_idle, payload)
    {ip, port} = data.peer
    UDP.send(data.udp, ip, port, packet)

    {:keep_state, %{data | prod_seq32: seq32, prod_seq16: seq16},
     [{{:timeout, :produce}, data.t2o_rpi_ms, :produce}]}
  end

  def handle_event({:timeout, :watchdog}, :watchdog, :established, data) do
    data.handler.connection_event(conn_info(data), :timeout)
    _ = ConnectionTable.unregister(data.table, data.triad)
    {:stop, :normal, data}
  end

  def handle_event(:info, :close, _state, data) do
    data.handler.connection_event(conn_info(data), :closed)
    {:stop, :normal, data}
  end

  def handle_event(_type, _event, _state, data), do: {:keep_state, data}

  defp read_stored(data) do
    {:ok, stored} = AssemblyStore.read(data.store, data.t2o_assembly)
    stored
  end

  defp track_run_idle(data, nil), do: data
  defp track_run_idle(%{run_state: mode} = data, mode), do: data

  defp track_run_idle(data, mode) do
    data.handler.run_idle_changed(conn_info(data), mode)
    %{data | run_state: mode}
  end

  defp conn_info(data) do
    %{triad: data.triad, o2t_connection_id: data.o2t_id,
      t2o_connection_id: data.t2o_id,
      o2t_assembly: data.o2t_assembly, t2o_assembly: data.t2o_assembly}
  end
end
```

CM object — replace `validate_transport/1` with class dispatch inside
`open_connection/2` (explicit flow unchanged for class 3) and add the IO flow
per the Interfaces list above. Key snippets:

```elixir
  defp open_connection(fo, ctx) do
    case fo.transport do
      %{class: 3} -> open_explicit(fo, ctx)   # existing body, renamed
      %{class: 1} -> open_io(fo, ctx)
      _ -> {:error, 0x01, [0x0103]}
    end
  end

  defp open_io(fo, ctx) do
    with :ok <- validate_io_types(fo),
         :ok <- validate_rpis(fo),
         {:ok, cfg, o2t_asm, t2o_asm} <- validate_io_path(fo),
         {:ok, out_size} <- assembly_kind(ctx, o2t_asm, :output, 0x012A),
         {:ok, in_size} <- assembly_kind(ctx, t2o_asm, :input, 0x012B),
         :ok <- validate_config_instance(ctx, cfg),
         :ok <- validate_io_size(fo.o2t_params.size, out_size,
                  ctx.config.io.o2t_run_idle, 0x0127),
         :ok <- validate_io_size(fo.t2o_params.size, in_size,
                  ctx.config.io.t2o_run_idle, 0x0128) do
      start_io_connection(fo, ctx, o2t_asm, t2o_asm)
    end
  end
```

with helpers returning `{:error, 0x01, [ext]}` shapes (and `[ext, correct_size]`
for the size checks); `start_io_connection/4`:

```elixir
  defp start_io_connection(fo, ctx, o2t_asm, t2o_asm) do
    triad = {fo.connection_serial, fo.originator_vendor_id, fo.originator_serial}
    peer = resolve_peer(ctx)

    args = %{
      table: ctx.connections, store: ctx.store, handler: ctx.handler,
      udp: ctx.config.io.udp, triad: triad,
      t2o_id: fo.t2o_connection_id,
      o2t_assembly: o2t_asm, t2o_assembly: t2o_asm,
      o2t_size: fo.o2t_params.size - overhead(ctx.config.io.o2t_run_idle),
      o2t_run_idle: ctx.config.io.o2t_run_idle,
      t2o_run_idle: ctx.config.io.t2o_run_idle,
      t2o_rpi_ms: Eipex.IO.rpi_ms(fo.t2o_rpi),
      watchdog_ms: Eipex.IO.rpi_ms(fo.o2t_rpi) * CM.timeout_factor(fo.timeout_multiplier)
    }

    {:ok, statem} =
      DynamicSupervisor.start_child(ctx.config.io.sup, {Eipex.Adapter.IoConnection, args})

    info = %{t2o_connection_id: fo.t2o_connection_id, kind: :io, pid: statem}

    # The monitored OWNER of a class 1 connection is the statem itself, NOT the
    # TCP session (class 1 connections survive session close per spec; they die
    # by watchdog or Forward Close). Passing the statem as the session argument
    # means both monitor paths point at the statem.
    case Eipex.Adapter.ConnectionTable.register(ctx.connections, triad, info, statem) do
      {:ok, o2t_id} ->
        Eipex.Adapter.IoConnection.activate(statem, o2t_id, peer)
        {:ok, udp_port} = Eipex.Adapter.UDP.port(ctx.config.io.udp)

        {:reply,
         CM.encode_forward_open_reply(%CM.ForwardOpenReply{
           o2t_connection_id: o2t_id, t2o_connection_id: fo.t2o_connection_id,
           connection_serial: fo.connection_serial,
           originator_vendor_id: fo.originator_vendor_id,
           originator_serial: fo.originator_serial,
           o2t_api: fo.o2t_rpi, t2o_api: fo.t2o_rpi, application_reply: <<>>
         }),
         [{:sockaddr_o2t, %{ip: {0, 0, 0, 0}, port: udp_port}}]}

      {:error, :duplicate} ->
        :gen_statem.stop(statem)
        {:error, 0x01, [0x0100]}

      {:error, :capacity} ->
        :gen_statem.stop(statem)
        {:error, 0x01, [0x0113]}
    end
  end

  defp overhead(run_idle?), do: 2 + if(run_idle?, do: 4, else: 0)

  defp resolve_peer(ctx) do
    case for {:sockaddr_t2o, sa} <- Map.get(ctx, :cpf_items, []), do: sa do
      [%{ip: {0, 0, 0, 0}, port: port} | _] -> {Map.get(ctx, :peer_ip, {127, 0, 0, 1}), port}
      [%{ip: ip, port: port} | _] -> {ip, port}
      [] -> {Map.get(ctx, :peer_ip, {127, 0, 0, 1}), 2222}
    end
  end
```

FC branch addition after `{:ok, record}`:

```elixir
          if record.kind == :io, do: send(record.pid, :close)
```

SessionHandler: capture `peer_ip` at activate (`{:ok, {ip, _port}} = :inet.peername(state.socket)`)
into state; pass `%{cpf_items: items, peer_ip: state.peer_ip}` to dispatch/3.

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/io_loopback_test.exs`
Expected: PASS, 9 tests. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter class 1 I/O connections: cyclic production, watchdog, run/idle`

```bash
mix format && git add -A && git commit -m "feat: adapter implicit io connections"
```

---

### Task 5: Scanner I/O connections (`open_io` + IOConnection statem)

**Files:**
- Create: `lib/eipex/scanner/io_connection.ex`
- Modify: `lib/eipex/scanner.ex` (io transaction plumbing, `open_io/2`, decode_reply extras)
- Test: `test/eipex/scanner/io_connection_test.exs` (loopback against the real adapter)

**Interfaces:**
- Consumes: everything above; the real adapter as the loopback peer.
- Produces:
  - Scanner internals:
    - `decode_reply/1` returns `{:ok, response, sockaddrs}` where `sockaddrs = [{:sockaddr_o2t | :sockaddr_t2o, map}]` extracted from the reply CPF (empty list normally). `settle_reply` branches for `:request` / `{:forward_open, _}` / `:forward_close` ignore the extras (mechanical signature update); transport-error tuples unchanged.
    - New call `{:io_forward_open, params, udp_port}` with pending kind `{:io_reply, from}` semantics: the SERVER builds the `%ForwardOpen{}` (its vendor/serial/counter; transport `%{direction: :server, trigger: :cyclic, class: 1}`; fixed-size params from `params`; path from `params.path_segments`), sends it with the extra CPF item `{:sockaddr_t2o, %{ip: {0,0,0,0}, port: udp_port}}`, and the settle branch replies `{:ok, fo, response, sockaddrs}` to the caller WITHOUT touching `state.connection` (class 3 only). Requires `send_request` to accept an `extra_cpf` list for UCMM sends (add an optional element to the payload tuple: `{:ucmm, mr, extra_cpf}`; plain binary payloads keep working).
    - New call `{:io_forward_close, triad, path}` → kind `:io_close` → replies `:ok | {:error, ...}` (0x0107 treated as `:ok`, mirroring Phase 4), no scanner-state mutation.
    - `Scanner.host(pid) :: {:ok, ip_tuple}` (from state; the statem needs it to resolve `{0,0,0,0}` sockaddrs).
  - `Eipex.Scanner.open_io(scanner, opts) :: {:ok, pid} | {:error, term}` — opts per the header sketch; starts (links) an `Eipex.Scanner.IOConnection`.
  - `Eipex.Scanner.IOConnection` (`:gen_statem`):
    - init: opens its own UDP socket (`port: 0`, active), calls the scanner's `{:io_forward_open, ...}`; on success resolves the peer from the reply's `sockaddr_o2t` (ip `{0,0,0,0}` → scanner host; item absent → `{scanner_host, 2222}`), enters `:running`, arms produce (o2t rpi) + watchdog (t2o rpi × factor) timers; on failure `{:error, reason}` is returned from `open_io` (use `:gen_statem.start_link` + init-blocking transaction; on FO failure return `{:stop, reason}` → `open_io` surfaces `{:error, reason}`).
    - Production: every o2t RPI sends `IO.encode_packet(o2t_id_from_reply, seq32, seq16, run_idle(:run when configured), output_buffer)` from its socket to the peer; `set_output(pid, data)` (size-checked) replaces the buffer (initial zeros).
    - Consumption: datagrams on its socket → `IO.decode_packet(dgram, t2o_run_idle)`; accept only `conn_id == t2o_connection_id` (the id the scanner proposed) + `seq_newer?`; notify `owner`: `{:eipex_io, pid, :data, data}` on payload CHANGE or first packet (dedup identical consecutive payloads to avoid flooding the owner at RPI rate), `{:eipex_io, pid, :run_idle, mode}` on header transitions.
    - Watchdog expiry → `{:eipex_io, pid, :timeout}` to owner → best-effort Forward Close through the scanner → stop `:normal`.
    - `close(pid)` → Forward Close via scanner → `{:eipex_io, pid, :closed}` → stop `:normal`.

- [ ] **Step 1: Write the failing tests**

`test/eipex/scanner/io_connection_test.exs`:

```elixir
defmodule Eipex.Scanner.IOConnectionTest do
  use ExUnit.Case

  alias Eipex.Scanner

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  defp start_pair(adapter_extra \\ []) do
    {:ok, adapter} =
      Eipex.Adapter.start_link(
        [identity: @identity,
         assemblies: [input: [instance: 100, size: 4],
                      output: [instance: 150, size: 4],
                      config: [instance: 151, size: 2]],
         port: 0, io_udp_port: 0] ++ adapter_extra)

    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner} =
      Scanner.start_link(host: {127, 0, 0, 1}, port: port,
                         vendor_id: 0x004D, serial_number: 0xDEAD_0001)

    {adapter, scanner}
  end

  defp open_io(scanner, extra \\ []) do
    Scanner.open_io(scanner,
      [o_to_t: [assembly: 150, size: 4, rpi: 20_000, run_idle: true],
       t_to_o: [assembly: 100, size: 4, rpi: 20_000, run_idle: false],
       config: [assembly: 151],
       timeout_multiplier: 0,
       owner: self()] ++ extra)
  end

  test "opens, consumes produced data, pushes output, closes" do
    {adapter, scanner} = start_pair()

    :ok = Eipex.Adapter.write_assembly(adapter, 100, <<1, 1, 2, 3>>)
    assert {:ok, io} = open_io(scanner)

    assert_receive {:eipex_io, ^io, :data, <<1, 1, 2, 3>>}, 1_000

    :ok = Eipex.Scanner.IOConnection.set_output(io, <<4, 3, 2, 1>>)
    assert eventually(fn -> Eipex.Adapter.read_assembly(adapter, 150) == {:ok, <<4, 3, 2, 1>>} end)

    assert :ok = Eipex.Scanner.IOConnection.close(io)
    assert_receive {:eipex_io, ^io, :closed}, 500
    refute Process.alive?(io)

    Scanner.close(scanner)
  end

  test "data change notifications dedup identical payloads" do
    {adapter, scanner} = start_pair()
    {:ok, io} = open_io(scanner)

    assert_receive {:eipex_io, ^io, :data, <<0, 0, 0, 0>>}, 1_000
    refute_receive {:eipex_io, ^io, :data, <<0, 0, 0, 0>>}, 200

    :ok = Eipex.Adapter.write_assembly(adapter, 100, <<5, 5, 5, 5>>)
    assert_receive {:eipex_io, ^io, :data, <<5, 5, 5, 5>>}, 1_000

    Eipex.Scanner.IOConnection.close(io)
    Scanner.close(scanner)
  end

  test "set_output validates size" do
    {_adapter, scanner} = start_pair()
    {:ok, io} = open_io(scanner)

    assert {:error, :size_mismatch} = Eipex.Scanner.IOConnection.set_output(io, <<1>>)

    Eipex.Scanner.IOConnection.close(io)
    Scanner.close(scanner)
  end

  test "forward open rejections surface as errors" do
    {_adapter, scanner} = start_pair()

    assert {:error, {:cip, :connection_failure, [0x0127, 10]}} =
             open_io(scanner, o_to_t: [assembly: 150, size: 9, rpi: 20_000, run_idle: true])

    Scanner.close(scanner)
  end

  defp eventually(fun, tries \\ 50) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(20) && eventually(fun, tries - 1)
    end
  end
end
```

(Note the rejection test: `size: 9` yields wire size 9+2+4=15 ≠ expected 10 —
the scanner passes the DATA size in opts; wire sizes are computed internally
via `Eipex.IO.wire_size/2`. Wait — expected extended is `[0x0127, 10]` because
the adapter's correct wire size for a 4-byte output with run/idle is 10. The
scanner must therefore send `size: 9` as a WIRE size to trigger it… resolve
this precisely: `open_io` computes wire sizes from the DATA size + run_idle
flags. To exercise the rejection, the test passes a wrong DATA size (9), the
scanner computes wire size 15, and the adapter answers `[0x0127, 10]`. The
assertion above is already consistent with that.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner/io_connection_test.exs`
Expected: FAIL — `Scanner.open_io/2` undefined.

- [ ] **Step 3: Implement**

Scanner-side plumbing (in `lib/eipex/scanner.ex`):

```elixir
  @spec open_io(GenServer.server(), keyword()) :: {:ok, pid()} | {:error, term()}
  def open_io(server, opts) do
    Eipex.Scanner.IOConnection.start_link(Map.new(opts) |> Map.put(:scanner, server))
  end

  @spec host(GenServer.server()) :: {:ok, :inet.ip4_address()}
  def host(server), do: GenServer.call(server, :host)

  @doc false
  def io_forward_open(server, params, udp_port),
    do: GenServer.call(server, {:io_forward_open, params, udp_port}, :infinity)

  @doc false
  def io_forward_close(server, triad, path),
    do: GenServer.call(server, {:io_forward_close, triad, path}, :infinity)
```

`handle_call(:host, ...)` replies the normalized host tuple (store it in State
at init — convert charlists via `:inet.getaddr(host, :inet)` once, at connect
time, keeping the resolved tuple).

`{:io_forward_open, params, udp_port}`: builds the FO like `build_forward_open`
but with `transport: %{direction: :server, trigger: :cyclic, class: 1}`,
`o2t_rpi/t2o_rpi` and fixed-size params from `params`, `timeout_multiplier`
from `params`, `connection_path: Path.encode(params.path_segments)`; dispatches
with kind `{:io_reply, fo}` and payload `{:ucmm, mr, [{:sockaddr_t2o, %{ip: {0, 0, 0, 0}, port: udp_port}}]}`.
`send_request` UCMM clause accepts the `{:ucmm, mr, extra_cpf}` payload shape
(CPF items appended after the two standard items); plain binary payload ≡
`{:ucmm, mr, []}`. `settle_reply({:io_reply, fo}, ...)`: success → reply
`{:ok, fo, response, sockaddrs}`; CIP error → `{:error, {:cip, name, extended}}`;
transport error passthrough. NO fallback, NO state.connection mutation.

`{:io_forward_close, triad, path}`: like `:forward_close` but kind `:io_close`
whose settle replies `:ok` on success or extended `[0x0107]`, error otherwise,
and never touches `state.connection`.

`decode_reply/1` → `{:ok, response, sockaddrs}` (collect `{:sockaddr_o2t, _}` /
`{:sockaddr_t2o, _}` items from the reply CPF); update every settle branch
signature (`settle_reply(kind, decoded, from, state)` where decoded is the
3-tuple or `{:error, _}`).

`lib/eipex/scanner/io_connection.ex` — the statem (abridged structure; write it
complete):

```elixir
defmodule Eipex.Scanner.IOConnection do
  @moduledoc """
  Scanner-side class 1 I/O connection: owns its UDP socket, produces O->T
  data on the RPI (run/idle Run), consumes T->O data with sequence checks and
  a watchdog, and notifies the owner process:
  `{:eipex_io, pid, :data, binary}` (on change), `{:eipex_io, pid, :run_idle, mode}`,
  `{:eipex_io, pid, :timeout}`, `{:eipex_io, pid, :closed}`.
  """

  @behaviour :gen_statem

  alias Eipex.IO

  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  def set_output(pid, data), do: :gen_statem.call(pid, {:set_output, data})
  def close(pid), do: :gen_statem.call(pid, :close)

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(args) do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: true])
    {:ok, udp_port} = :inet.port(socket)

    o2t = Map.new(args.o_to_t)
    t2o = Map.new(args.t_to_o)

    path_segments =
      [{:class, 0x04}] ++
        case args[:config] do
          nil -> []
          config -> [{:instance, Keyword.fetch!(config, :assembly)}]
        end ++
        [{:connection_point, o2t.assembly}, {:connection_point, t2o.assembly}]

    params = %{
      o2t_size: IO.wire_size(o2t.size, o2t[:run_idle] || false),
      t2o_size: IO.wire_size(t2o.size, t2o[:run_idle] || false),
      o2t_rpi: o2t.rpi, t2o_rpi: t2o.rpi,
      timeout_multiplier: args[:timeout_multiplier] || 2,
      path_segments: path_segments
    }

    case Eipex.Scanner.io_forward_open(args.scanner, params, udp_port) do
      {:ok, fo, response, sockaddrs} ->
        {:ok, reply} =
          Eipex.CIP.ConnectionManager.decode_forward_open_reply(response.data)

        {:ok, host} = Eipex.Scanner.host(args.scanner)
        peer = resolve_peer(sockaddrs, host)

        data = %{
          socket: socket, owner: args.owner, scanner: args.scanner,
          o2t_id: reply.o2t_connection_id, t2o_id: fo.t2o_connection_id,
          triad: {fo.connection_serial, fo.originator_vendor_id, fo.originator_serial},
          path: fo.connection_path, peer: peer,
          o2t_run_idle: o2t[:run_idle] || false, t2o_run_idle: t2o[:run_idle] || false,
          o2t_size: o2t.size, output: :binary.copy(<<0>>, o2t.size),
          produce_ms: IO.rpi_ms(o2t.rpi),
          watchdog_ms:
            IO.rpi_ms(t2o.rpi) *
              Eipex.CIP.ConnectionManager.timeout_factor(params.timeout_multiplier),
          prod_seq32: 0, prod_seq16: 0, last_seq32: nil, last_data: nil, run_state: nil
        }

        {:ok, :running, data,
         [{{:timeout, :produce}, data.produce_ms, :produce},
          {{:timeout, :watchdog}, data.watchdog_ms, :watchdog}]}

      {:error, reason} ->
        :gen_udp.close(socket)
        {:stop, reason}
    end
  end

  defp resolve_peer(sockaddrs, host) do
    case for {:sockaddr_o2t, sa} <- sockaddrs, do: sa do
      [%{ip: {0, 0, 0, 0}, port: port} | _] -> {host, port}
      [%{ip: ip, port: port} | _] -> {ip, port}
      [] -> {host, 2222}
    end
  end

  # production / consumption / watchdog / close events follow the adapter
  # IoConnection's structure; consumption notifies the owner on data CHANGE
  # (compare with last_data), run/idle transitions notify on change; close/1
  # calls Eipex.Scanner.io_forward_close(scanner, triad, path) then notifies
  # {:eipex_io, self(), :closed} and stops; watchdog notifies :timeout, does a
  # best-effort io_forward_close, and stops. set_output validates
  # byte_size(data) == o2t_size -> {:error, :size_mismatch} otherwise.
end
```

(Write the full event clauses — mirror `Eipex.Adapter.IoConnection`, they are
symmetric; production sends via `:gen_udp.send(data.socket, ip, port, packet)`
directly since the statem owns its socket.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner/io_connection_test.exs`
Expected: PASS, 4 tests. Full `mix test` green (scanner suites confirm the
decode_reply/settle signature updates broke nothing).

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner open_io: class 1 I/O connections with owner notifications`

```bash
mix format && git add -A && git commit -m "feat: scanner implicit io connections"
```

---

### Task 6: Full I/O loopback matrix

**Files:**
- Test: `test/eipex/adapter/io_loopback_test.exs` (append a describe block using the real scanner)

**Interfaces:** consumes Tasks 4-5. Produces the cross-role guarantees:

- [ ] **Step 1: Write the tests** (append `describe "scanner loopback matrix"`; start a
pair per test like Task 5's helper; register the test pid as `:io_loopback_test`
for handler messages — reuse the module's setup where practical):

1. **run/idle transition reaches the adapter handler**: scanner `open_io` (o2t run_idle true) → adapter handler receives `{:run_idle, :run}` exactly once (scanner always produces Run).
2. **adapter watchdog fires when the scanner dies**: `Process.exit(io, :kill)` → adapter handler gets `{:conn_event, :timeout}` within `watchdog + slack`; triad freed (reopen same scanner succeeds — note the scanner's serial counter gives a fresh triad anyway, so assert via `ConnectionTable`-observable behavior: a new open_io succeeds and produces).
3. **scanner watchdog fires when the adapter connection dies**: find the adapter's io statem (`DynamicSupervisor.which_children(config.io.sup)` via `:sys.get_state(adapter)`) and kill it → owner receives `{:eipex_io, io, :timeout}` within watchdog + slack; the io process stops.
4. **stale O→T sequence does not regress adapter state** (covered raw in Task 4 — here assert through the scanner: two quick `set_output` values land in order; final store value is the LAST one after settling).
5. **capacity applies to io connections**: adapter `max_connections: 1` → first open_io ok, second scanner's open_io → `{:error, {:cip, :connection_failure, [0x0113]}}`.
6. **close frees capacity**: close the first io; a second open_io then succeeds.

- [ ] **Step 2: Run, fix integration bugs (document each), pass**

Run: `mix test test/eipex/adapter/io_loopback_test.exs`
Expected: PASS (9 raw + 6 scanner-matrix). Full `mix test` green. Timing note:
RPIs 20 ms, multiplier 0 (factor 4 → 80 ms watchdogs); use generous
`assert_receive` timeouts (≥ 1 s) to stay CI-safe.

- [ ] **Step 3: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Cross-role implicit I/O loopback matrix`

```bash
mix format && git add -A && git commit -m "test: io loopback matrix"
```

---

### Task 7: OpENer interop

**Files:**
- Create: `interop/opener/Dockerfile`
- Modify: `interop/docker-compose.yml` (add the `opener` service), `README.md`
- Create: `test/interop/opener_test.exs`

**Interfaces:** consumes the full scanner I/O stack. REAL RUN MANDATORY.

- [ ] **Step 1: Dockerfile + compose**

`interop/opener/Dockerfile`:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake gcc make ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/EIPStackGroup/OpENer.git /opener
WORKDIR /opener/build
RUN cmake -DOpENer_PLATFORM:STRING=POSIX ../source && make -j"$(nproc)"
CMD ["./src/ports/POSIX/OpENer", "lo"]
```

Compose service (append to `interop/docker-compose.yml`):

```yaml
  opener:
    build: ./opener
    network_mode: host
    command: ["./src/ports/POSIX/OpENer", "lo"]
```

(`network_mode: host` + interface `lo`: OpENer binds TCP/UDP 44818 and UDP 2222
on the host loopback. The interop test therefore talks to 127.0.0.1:44818.)

- [ ] **Step 2: Interop test**

`test/interop/opener_test.exs`:

```elixir
defmodule Eipex.Interop.OpenerTest do
  @moduledoc """
  Interop against OpENer (the ODVA reference adapter, C).
  Start it first: docker compose -f interop/docker-compose.yml up -d --build opener
  Run with: mix test --include interop test/interop/opener_test.exs
  """

  use ExUnit.Case

  alias Eipex.Scanner

  @moduletag :interop
  @moduletag timeout: 600_000
  @host System.get_env("OPENER_HOST", "127.0.0.1")

  test "identity, explicit assembly access and class 1 I/O against OpENer" do
    {:ok, scanner} = Scanner.start_link(host: @host, vendor_id: 0x004D)

    # OpENer's vendor id is 365 (0x016D)
    assert {:ok, <<vendor::16-little>>} = Scanner.get_attribute(scanner, 0x01, 1, 1)
    assert vendor == 365

    # sample app assemblies: input 100, output 150, config 151, 32 bytes each
    {:ok, io} =
      Scanner.open_io(scanner,
        o_to_t: [assembly: 150, size: 32, rpi: 100_000, run_idle: true],
        t_to_o: [assembly: 100, size: 32, rpi: 100_000, run_idle: false],
        config: [assembly: 151],
        timeout_multiplier: 2,
        owner: self())

    assert_receive {:eipex_io, ^io, :data, data}, 5_000
    assert byte_size(data) == 32

    # write output data cyclically, then read assembly 150 back explicitly
    payload = :binary.copy(<<0xA5>>, 32)
    :ok = Eipex.Scanner.IOConnection.set_output(io, payload)
    Process.sleep(500)

    assert {:ok, ^payload} = Scanner.get_attribute(scanner, 0x04, 150, 3)

    :ok = Eipex.Scanner.IOConnection.close(io)
    assert_receive {:eipex_io, ^io, :closed}, 1_000

    Scanner.close(scanner)
  end
end
```

- [ ] **Step 3: Run it for real**

```bash
docker compose -f interop/docker-compose.yml up -d --build opener
sleep 5
mix test --include interop test/interop/opener_test.exs
docker compose -f interop/docker-compose.yml down
```

Expected: 1 test, 0 failures (first build takes minutes). ADAPT to observed
OpENer reality and document EVERYTHING in the report: if assembly sizes differ
(watch for 0x0127/0x0128 extended — the second word tells you the size OpENer
wants), adjust sizes; if OpENer requires run/idle differently, adjust flags; if
`lo` doesn't work as its interface, try the host's primary interface name via
`OPENER_HOST`/compose command override. Confirm hermetic `mix test` still
excludes it.

- [ ] **Step 4: README + commit**

README interop section gains the OpENer lines above. Append to `CHANGELOG.md`:
`- [Added] OpENer interop harness for class 1 I/O`

```bash
mix format && git add -A && git commit -m "test: opener interop"
```

---

### Task 8: Docs polish

**Files:**
- Modify: `lib/eipex/scanner.ex`, `lib/eipex/adapter/adapter.ex` (moduledocs mention implicit I/O; `@doc` for `open_io/2`, `io_udp_port/1`), `README.md` (I/O example)

- [ ] **Step 1:** Add `@doc` to `Scanner.open_io/2` (opts table, owner message shapes, the point-to-point/exclusive-owner-only scope note) and update both moduledocs + a README usage example mirroring the header sketch. No behavior changes.

- [ ] **Step 2:** `mix format && mix test` (green), `mix compile --warnings-as-errors` clean.

- [ ] **Step 3:** Append to `CHANGELOG.md`: `- [Added] Implicit I/O documentation and usage examples`

```bash
git add -A && git commit -m "docs: implicit io documentation"
```

---

## Completion criteria for Phase 5

- `mix test` green and hermetic (I/O loopback runs entirely on loopback UDP/TCP with ephemeral ports).
- Raw + scanner loopback I/O matrix green (production, consumption, run/idle, both watchdog directions, sequence rules, size/type/path validation, capacity).
- `mix test --include interop` green for OpENer class 1 I/O (real run, output in the report) — plus the existing cpppo/pycomm3 suites still green.
- `mix format --check-formatted`; zero runtime deps; one CHANGELOG line per task.

## After this plan

Phase 6 (scanner Logix services: tag list, templates/UDTs, fragmentation, MSP —
validated against cpppo) is pure scanner-side work over the existing session +
connected machinery. Phase 7 (docs, EDS sample, hex.pm release) closes v0.1.0.
Deferred from this phase: multicast (allocation/join), input-only/listen-only
connection points and cascade closes, config-data segments.

