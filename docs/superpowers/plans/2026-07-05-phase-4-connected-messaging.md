# Eipex Phase 4 — Connected Class 3 Messaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connected explicit messaging (transport class 3) in both roles: the scanner opens/closes CIP connections (Forward Open with large→standard fallback, Forward Close) and sends requests over SendUnitData with sequence counts; the adapter validates Forward Opens (transport class, path, duplicate triad, capacity), serves connected requests with sequence dedup + reply caching, and cleans up connections when sessions die. Validated by loopback (our scanner ↔ our adapter) and a real pycomm3 connected-messaging run.

**Architecture:** Class 3 connections ride the TCP session. Scanner: at most ONE explicit connection per session (pycomm3's model); connection state (ids, serial, 16-bit sequence) lives in the Scanner state; the pending-request tuple gains a `kind` so Forward Open/Close replies get server-side post-processing (store/clear the connection, large→standard retry) before answering the caller. Adapter: a `ConnectionTable` GenServer (owned by the adapter, monitors session pids for auto-cleanup) tracks triads/ids/capacity across sessions; the ConnectionManager object validates and registers Forward Opens; the SessionHandler serves SendUnitData with per-connection sequence dedup and last-reply caching. Class 0/1 Forward Opens answer extended status 0x0103 until Phase 5.

**Deviation from spec §5 (documented):** class 3 connections have no per-connection inactivity watchdog in this phase — they die with the TCP session (the 120 s encapsulation inactivity timeout covers dead sessions). The Phase 5 `gen_statem` connection model adds real watchdogs for class 1 and can absorb class 3 then.

**Tech Stack:** Elixir/OTP only. Phase 1 codecs extended (Task 1). ScriptedTarget extended for SendUnitData. pycomm3 interop script extended.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. No mocks — ScriptedTarget, raw gen_tcp, our own scanner/adapter as clients.
- `decode`-side functions never raise on network input; wrong/unknown connected frames are dropped (no route back), malformed ones answer the correct encap/CIP status.
- One SessionHandler crash must never take down the listener; a dead session must release its connections (ConnectionTable monitors).
- `mix format` before every commit. One CHANGELOG line per commit: `[Type] What changed`, ≤100 chars, appended at the bottom.
- TDD: failing test first, watch it fail, implement, watch it pass, commit.
- Phase 1-3 suites (164 tests + 3 properties) stay green throughout.

## File Structure

```
eipex/
├── lib/eipex/
│   ├── cip/connection_manager.ex        # Task 1: FC reply + FO error-reply codecs, 2 ext statuses
│   ├── scanner.ex                       # Tasks 2-3: forward_open/close, connected requests; Task 7: narrowed rescue
│   ├── adapter/
│   │   ├── connection_table.ex          # Task 4: triad/id registry with monitors + capacity
│   │   ├── config.ex                    # Task 4: + connections field
│   │   ├── adapter.ex                   # Task 4: start ConnectionTable; max_connections opt
│   │   ├── message_router.ex            # Task 4: ctx gains session + connections
│   │   ├── object/connection_manager.ex # Task 4: real FO/LFO/FC handling
│   │   └── session_handler.ex           # Task 5: SendUnitData; Task 7: version check
├── test/support/scripted_target.ex      # Task 3: unit_handler opt
├── test/eipex/scanner_connected_test.exs        # Tasks 2-3
├── test/eipex/adapter/connection_table_test.exs # Task 4
├── test/eipex/adapter/connected_objects_test.exs# Task 4 (dispatch-level FO/FC)
├── test/eipex/adapter/connected_session_test.exs# Task 5 (raw gen_tcp)
├── test/eipex/adapter/connected_loopback_test.exs # Task 6
└── interop/pycomm3/check_adapter.py     # Task 6: connected read + close
```

**Public API after this phase:**

```elixir
{:ok, conn} = Eipex.Scanner.forward_open(scanner)
# conn :: %{o2t_connection_id, t2o_connection_id, connection_serial, size, variant}
# opts: variant: :large (default, falls back to :standard on CIP rejection) | :standard
# scanner start_link gains: vendor_id (default 0xFFFF), serial_number (default random 32-bit)

{:ok, resp} = Eipex.Scanner.generic_message(scanner,
                service: 0x0E, class: 1, instance: 1, attribute: 7, connected: true)
# connected requests bypass route wrapping (the route was baked into the FO path)
# without an open connection -> {:error, :no_connection}

:ok = Eipex.Scanner.forward_close(scanner)   # {:error, :no_connection} if none

{:ok, adapter} = Eipex.Adapter.start_link(..., max_connections: 8)
```

Adapter Forward Open validation order and answers (general status 0x01 + extended):
transport class ≠ 3 → 0x0103 · connection path not (optional port segments +)
`[class: 0x02, instance: 1]` → 0x0315 · duplicate triad → 0x0100 · capacity → 0x0113.
Forward Close on an unknown triad → 0x01 + 0x0107.

---

### Task 1: Codec additions (Forward Close reply, Forward Open error reply, ext statuses)

**Files:**
- Modify: `lib/eipex/cip/connection_manager.ex`
- Test: `test/eipex/cip/connection_manager_test.exs` (append)

**Interfaces:**
- Consumes: existing CM codec.
- Produces:
  - `CM.encode_forward_close_reply(triad) :: binary` — `<<serial::16-little, vendor::16-little, orig_serial::32-little, 0 (app reply words), 0 (reserved)>>`
  - `CM.decode_forward_close_reply(binary) :: {:ok, %{connection_serial, originator_vendor_id, originator_serial}} | {:error, :malformed_reply}`
  - `CM.decode_forward_open_error(binary) :: {:ok, %{connection_serial, originator_vendor_id, originator_serial, remaining_path_size}} | {:error, :malformed_reply}` — the unsuccessful-FO reply body (closes a Phase 2 deferred finding)
  - `ext_status_name/1` gains `0x0103 => :transport_trigger_not_supported` and `0x0107 => :target_connection_not_found`

- [ ] **Step 1: Write the failing tests (append to `test/eipex/cip/connection_manager_test.exs`)**

```elixir
  test "forward close reply round-trips" do
    triad = %{connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
              originator_serial: 0xDEAD_0001}

    reply = CM.encode_forward_close_reply(triad)

    assert reply ==
             <<0xBEEF::16-little, 0x004D::16-little, 0xDEAD_0001::32-little, 0, 0>>

    assert {:ok, %{connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
                   originator_serial: 0xDEAD_0001}} = CM.decode_forward_close_reply(reply)

    assert {:error, :malformed_reply} = CM.decode_forward_close_reply(<<1, 2, 3>>)
  end

  test "forward open error reply decodes the triad" do
    body = <<0xBEEF::16-little, 0x004D::16-little, 0xDEAD_0001::32-little, 1, 0>>

    assert {:ok, %{connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
                   originator_serial: 0xDEAD_0001, remaining_path_size: 1}} =
             CM.decode_forward_open_error(body)

    assert {:error, :malformed_reply} = CM.decode_forward_open_error(<<1, 2>>)
  end

  test "new extended status names" do
    assert CM.ext_status_name(0x0103) == :transport_trigger_not_supported
    assert CM.ext_status_name(0x0107) == :target_connection_not_found
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/connection_manager_test.exs`
Expected: FAIL — functions undefined; ext statuses map to `:unknown`.

- [ ] **Step 3: Implement**

In `Eipex.CIP.ConnectionManager`, add the two entries to `@ext_statuses`:

```elixir
    0x0103 => :transport_trigger_not_supported,
    0x0107 => :target_connection_not_found,
```

and after the Forward Close section:

```elixir
  @spec encode_forward_close_reply(map()) :: binary()
  def encode_forward_close_reply(triad) do
    <<triad.connection_serial::16-little, triad.originator_vendor_id::16-little,
      triad.originator_serial::32-little, 0, 0>>
  end

  @spec decode_forward_close_reply(binary()) :: {:ok, map()} | {:error, :malformed_reply}
  def decode_forward_close_reply(<<serial::16-little, vendor::16-little,
                                   orig_serial::32-little, _app_words, _reserved,
                                   _app_reply::binary>>) do
    {:ok,
     %{connection_serial: serial, originator_vendor_id: vendor,
       originator_serial: orig_serial}}
  end

  def decode_forward_close_reply(_), do: {:error, :malformed_reply}

  @spec decode_forward_open_error(binary()) :: {:ok, map()} | {:error, :malformed_reply}
  def decode_forward_open_error(<<serial::16-little, vendor::16-little,
                                  orig_serial::32-little, remaining_path_size,
                                  _reserved, _rest::binary>>) do
    {:ok,
     %{connection_serial: serial, originator_vendor_id: vendor,
       originator_serial: orig_serial, remaining_path_size: remaining_path_size}}
  end

  def decode_forward_open_error(_), do: {:error, :malformed_reply}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/connection_manager_test.exs`
Expected: PASS. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Forward Close reply and Forward Open error-reply codecs`

```bash
mix format && git add -A && git commit -m "feat: connected-messaging codec additions"
```

---

### Task 2: Scanner Forward Open / Forward Close

**Files:**
- Modify: `lib/eipex/scanner.ex`
- Test: `test/eipex/scanner_connected_test.exs` (new)

**Interfaces:**
- Consumes: `CM.encode_forward_open/2`, `CM.decode_forward_open_reply/1`, `CM.encode_forward_close/3`, `CM.decode_forward_close_reply/1`, `%CM.ForwardOpen{}` (Phase 1), Task 1 additions; ScriptedTarget (UCMM handler is enough — FO/FC are unconnected).
- Produces:
  - `Scanner.start_link` opts gain `vendor_id` (default `0xFFFF`) and `serial_number` (default: random 32-bit derived at init) — stored in State together with `connection_serial_counter` (starts 1) and `connection: nil`.
  - `Scanner.forward_open(server, opts \\ []) :: {:ok, conn_info} | {:error, term}` — `variant: :large` default; on a CIP-error reply to a `:large` attempt, the server IMMEDIATELY retries `:standard` on the same pending caller (one fallback, then report the error). `conn_info :: %{o2t_connection_id, t2o_connection_id, connection_serial, size, variant}`. `{:error, :already_connected}` if a connection exists.
  - `Scanner.forward_close(server) :: :ok | {:error, term}` — `{:error, :no_connection}` if none; on success clears the connection.
  - Internal: `State.pending` becomes `{from, context, timer, kind}` with `kind :: :request | {:forward_open, meta} | :forward_close`; ALL existing pending call sites updated (`send_request/5` gains the kind arg, queue entries `{from, mr, timeout, kind}`, `handle_frame`, `request_timeout`, `fail_callers`, `next_request`).
  - Forward Open parameters: priority_time_tick `0x0A`, timeout_ticks 10, o2t_connection_id 0, t2o_connection_id = random 32-bit, timeout_multiplier 1, both RPIs `10_000_000` µs, params `%{owner: :exclusive, type: :point_to_point, priority: :low, size_type: :variable, size: 4002 | 500}`, transport `%{direction: :server, trigger: :application, class: 3}`, connection path = route segments (from state.route_path, `[]` when `:none`) ++ `[class: 0x02, instance: 0x01]`.

- [ ] **Step 1: Write the failing tests**

`test/eipex/scanner_connected_test.exs`:

```elixir
defmodule Eipex.ScannerConnectedTest do
  use ExUnit.Case

  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter
  alias Eipex.Scanner
  alias Eipex.TestSupport.ScriptedTarget

  defp fo_success_handler(opts \\ []) do
    o2t = Keyword.get(opts, :o2t_id, 0xAAAA_0001)
    reject_large = Keyword.get(opts, :reject_large, false)

    fn mr ->
      case MessageRouter.decode_request(mr) do
        {:ok, %{service: 0x5B, data: data}} when reject_large ->
          {:ok, fo} = CM.decode_forward_open(0x5B, data)
          _ = fo
          MessageRouter.encode_response(0x5B, 0x01, extended: [0x0128])

        {:ok, %{service: service, data: data}} when service in [0x54, 0x5B] ->
          {:ok, fo} = CM.decode_forward_open(service, data)

          reply = %CM.ForwardOpenReply{
            o2t_connection_id: o2t,
            t2o_connection_id: fo.t2o_connection_id,
            connection_serial: fo.connection_serial,
            originator_vendor_id: fo.originator_vendor_id,
            originator_serial: fo.originator_serial,
            o2t_api: fo.o2t_rpi, t2o_api: fo.t2o_rpi,
            application_reply: <<>>
          }

          MessageRouter.encode_response(service, 0x00,
            data: CM.encode_forward_open_reply(reply))

        {:ok, %{service: 0x4E, data: data}} ->
          {:ok, fc} = CM.decode_forward_close(data)

          MessageRouter.encode_response(0x4E, 0x00,
            data: CM.encode_forward_close_reply(fc))
      end
    end
  end

  defp start_scanner(target, opts \\ []) do
    {:ok, pid} =
      Scanner.start_link([host: {127, 0, 0, 1}, port: target.port,
                          vendor_id: 0x004D, serial_number: 0xDEAD_0001] ++ opts)

    pid
  end

  test "forward_open stores the connection with large params by default" do
    target = ScriptedTarget.start(fo_success_handler())
    pid = start_scanner(target)

    assert {:ok, conn} = Scanner.forward_open(pid)
    assert conn.o2t_connection_id == 0xAAAA_0001
    assert conn.variant == :large
    assert conn.size == 4002
    assert conn.connection_serial == 1

    assert {:error, :already_connected} = Scanner.forward_open(pid)
    Scanner.close(pid)
  end

  test "large rejection falls back to a standard forward open" do
    target = ScriptedTarget.start(fo_success_handler(reject_large: true))
    pid = start_scanner(target)

    assert {:ok, %{variant: :standard, size: 500}} = Scanner.forward_open(pid)
    Scanner.close(pid)
  end

  test "standard rejection reports the CIP error without retry" do
    handler = fn mr ->
      {:ok, %{service: service}} = MessageRouter.decode_request(mr)
      MessageRouter.encode_response(service, 0x01, extended: [0x0113])
    end

    target = ScriptedTarget.start(handler)
    pid = start_scanner(target)

    assert {:error, {:cip, :connection_failure, [0x0113]}} =
             Scanner.forward_open(pid, variant: :standard)

    Scanner.close(pid)
  end

  test "forward_close clears the connection" do
    target = ScriptedTarget.start(fo_success_handler())
    pid = start_scanner(target)

    assert {:error, :no_connection} = Scanner.forward_close(pid)
    {:ok, _conn} = Scanner.forward_open(pid)
    assert :ok = Scanner.forward_close(pid)
    assert {:error, :no_connection} = Scanner.forward_close(pid)

    # can open again after closing
    assert {:ok, %{connection_serial: 2}} = Scanner.forward_open(pid)
    Scanner.close(pid)
  end

  test "forward open request carries the configured identity and MR path" do
    test_pid = self()

    handler = fn mr ->
      {:ok, %{service: 0x5B, data: data}} = MessageRouter.decode_request(mr)
      {:ok, fo} = CM.decode_forward_open(0x5B, data)
      send(test_pid, {:fo, fo})

      reply = %CM.ForwardOpenReply{
        o2t_connection_id: 1, t2o_connection_id: fo.t2o_connection_id,
        connection_serial: fo.connection_serial,
        originator_vendor_id: fo.originator_vendor_id,
        originator_serial: fo.originator_serial,
        o2t_api: fo.o2t_rpi, t2o_api: fo.t2o_rpi, application_reply: <<>>
      }

      MessageRouter.encode_response(0x5B, 0x00, data: CM.encode_forward_open_reply(reply))
    end

    target = ScriptedTarget.start(handler)
    pid = start_scanner(target)
    {:ok, _} = Scanner.forward_open(pid)

    assert_receive {:fo, fo}
    assert fo.originator_vendor_id == 0x004D
    assert fo.originator_serial == 0xDEAD_0001
    assert fo.transport == %{direction: :server, trigger: :application, class: 3}
    assert {:ok, [class: 0x02, instance: 0x01]} = Eipex.CIP.Path.decode(fo.connection_path)

    Scanner.close(pid)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_connected_test.exs`
Expected: FAIL — `Scanner.forward_open/1` undefined.

- [ ] **Step 3: Implement**

In `lib/eipex/scanner.ex` (the `ConnectionManager` alias already exists; ADD
`alias Eipex.CIP.Path` — `build_forward_open` uses it). `settle_reply/4` always
returns `{:ok, state} | {:lost, state}` — every branch ends in `next_request/1`
or `send_request/5`, both of which are tagged after the Phase 2 fix.

State additions:

```elixir
              vendor_id: 0xFFFF,
              serial_number: 0,
              connection_serial_counter: 1,
              connection: nil,
```

`init/1` additions (after the existing option reads):

```elixir
         vendor_id: Keyword.get(opts, :vendor_id, 0xFFFF),
         serial_number:
           Keyword.get_lazy(opts, :serial_number, fn ->
             Bitwise.band(:erlang.unique_integer([:positive]), 0xFFFF_FFFF)
           end),
```

Public API:

```elixir
  @spec forward_open(GenServer.server(), keyword()) :: {:ok, map()} | {:error, term()}
  def forward_open(server, opts \\ []) do
    GenServer.call(server, {:forward_open, opts}, :infinity)
  end

  @spec forward_close(GenServer.server()) :: :ok | {:error, term()}
  def forward_close(server), do: GenServer.call(server, :forward_close, :infinity)
```

New `handle_call` clauses:

```elixir
  def handle_call({:forward_open, _opts}, _from, %State{connection: conn} = state)
      when not is_nil(conn) do
    {:reply, {:error, :already_connected}, state}
  end

  def handle_call({:forward_open, opts}, from, state) do
    variant = Keyword.get(opts, :variant, :large)
    {fo, state} = build_forward_open(state, variant)
    mr = ConnectionManager.encode_forward_open(fo, variant)
    meta = %{fo: fo, variant: variant, fallback: variant == :large}
    dispatch_request(state, from, mr, state.timeout, {:forward_open, meta})
  end

  def handle_call(:forward_close, _from, %State{connection: nil} = state) do
    {:reply, {:error, :no_connection}, state}
  end

  def handle_call(:forward_close, from, state) do
    conn = state.connection

    triad = %{connection_serial: conn.connection_serial,
              originator_vendor_id: state.vendor_id,
              originator_serial: state.serial_number}

    mr = ConnectionManager.encode_forward_close(triad, conn.connection_path, [])
    dispatch_request(state, from, mr, state.timeout, :forward_close)
  end
```

Refactor the existing `{:request, opts}` clause's send/queue block into a shared
helper (the queue entry and `send_request` gain the `kind`):

```elixir
  defp dispatch_request(state, from, mr, timeout, kind) do
    if state.pending do
      {:noreply, %{state | queue: :queue.in({from, mr, timeout, kind}, state.queue)}}
    else
      case send_request(state, from, mr, timeout, kind) do
        {:ok, state} -> {:noreply, state}
        {:lost, state} ->
          {:stop, {:shutdown, :connection_lost},
           fail_callers(state, {:error, :connection_lost})}
      end
    end
  end
```

(the `{:request, opts}` success branch becomes `dispatch_request(state, from, mr, timeout, :request)`; `send_request/5` stores `pending: {from, context, timer, kind}`; `next_request/1` pops 4-tuples; `handle_info({:request_timeout, ...})` and `fail_callers/2` match the 4-tuple.)

Forward Open construction:

```elixir
  defp build_forward_open(state, variant) do
    serial = state.connection_serial_counter

    route =
      case state.route_path do
        :none -> []
        segments -> segments
      end

    fo = %ConnectionManager.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: Bitwise.band(:erlang.unique_integer([:positive]), 0xFFFF_FFFF),
      connection_serial: serial,
      originator_vendor_id: state.vendor_id,
      originator_serial: state.serial_number,
      timeout_multiplier: 1,
      o2t_rpi: 10_000_000,
      o2t_params: connection_params(variant),
      t2o_rpi: 10_000_000,
      t2o_params: connection_params(variant),
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(route ++ [class: 0x02, instance: 0x01])
    }

    {fo, %{state | connection_serial_counter: serial + 1}}
  end

  defp connection_params(:large),
    do: %{owner: :exclusive, type: :point_to_point, priority: :low,
          size_type: :variable, size: 4002}

  defp connection_params(:standard),
    do: %{owner: :exclusive, type: :point_to_point, priority: :low,
          size_type: :variable, size: 500}
```

Reply post-processing — `handle_frame`'s pending clause routes by kind:

```elixir
  defp handle_frame(
         %State{pending: {from, context, timer, kind}} = state,
         %Encap{command: :send_rr_data, sender_context: context} = frame
       ) do
    Process.cancel_timer(timer)
    settle_reply(kind, decode_reply(frame), from, %{state | pending: nil})
  end

  defp settle_reply(:request, reply, from, state) do
    GenServer.reply(from, reply)
    next_request(state)
  end

  defp settle_reply({:forward_open, meta}, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success, data: data}} ->
        case ConnectionManager.decode_forward_open_reply(data) do
          {:ok, fo_reply} ->
            conn = %{
              o2t_connection_id: fo_reply.o2t_connection_id,
              t2o_connection_id: fo_reply.t2o_connection_id,
              connection_serial: meta.fo.connection_serial,
              connection_path: meta.fo.connection_path,
              size: meta.fo.o2t_params.size,
              variant: meta.variant,
              seq: 1
            }

            GenServer.reply(from, {:ok, Map.drop(conn, [:seq, :connection_path])})
            next_request(%{state | connection: conn})

          {:error, reason} ->
            GenServer.reply(from, {:error, reason})
            next_request(state)
        end

      {:ok, %{status_name: _name, extended: _extended}} when meta.fallback ->
        {fo, state} = build_forward_open(state, :standard)
        mr = ConnectionManager.encode_forward_open(fo, :standard)
        meta = %{fo: fo, variant: :standard, fallback: false}

        # send_request returns {:ok, state} | {:lost, state} — propagate the tag
        # verbatim (on :lost it already replied {:error, :connection_lost} to from)
        send_request(state, from, mr, state.timeout, {:forward_open, meta})

      {:ok, %{status_name: name, extended: extended}} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end

  defp settle_reply(:forward_close, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success}} ->
        GenServer.reply(from, :ok)
        next_request(%{state | connection: nil})

      {:ok, %{status_name: name, extended: extended}} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end
```

Note on the fallback branch: `send_request` may itself return `{:lost, state}`;
returning the state lets the imminent `{:tcp_closed, ...}` (or the caller-reply
inside `send_request`'s failure branch) finish the job — the caller was already
answered `{:error, :connection_lost}` there. `next_request/1` returns `{:ok, state} |
{:lost, state}`; `settle_reply` callers in `handle_frame`/`request_timeout` must
propagate that tag exactly as Phase 2's fix did (walk every call site).

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_connected_test.exs`
Expected: PASS, 5 tests. Full `mix test` green (existing scanner tests confirm the
pending 4-tuple refactor broke nothing).

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner Forward Open/Close with large-to-standard fallback`

```bash
mix format && git add -A && git commit -m "feat: scanner forward open and close"
```

---

### Task 3: Scanner connected requests (SendUnitData)

**Files:**
- Modify: `lib/eipex/scanner.ex`
- Modify: `test/support/scripted_target.ex` (`unit_handler:` opt)
- Test: `test/eipex/scanner_connected_test.exs` (append)

**Interfaces:**
- Consumes: Task 2's connection state; `Encap.send_unit_data/2`, CPF connected items (Phase 1).
- Produces:
  - `generic_message(server, opts)` accepts `connected: true`: builds the MR request WITHOUT route wrapping, prefixes the 16-bit sequence count, wraps in CPF `[{:connected_address, conn.o2t_connection_id}, {:connected_data, <<seq::16-little, mr>>}]`, sends via SendUnitData. `{:error, :no_connection}` when no connection. `conn.seq` increments per request, wrapping at 0xFFFF back to 1.
  - Correlation: a new `handle_frame` clause for `%Encap{command: :send_unit_data}` matching pending kind `{:connected, t2o_id, seq}` — decodes the CPF, requires `{:connected_address, t2o_id}` and the echoed `seq`, then `MessageRouter.decode_response/1` on the rest of the connected data. Mismatched/unsolicited SendUnitData frames are ignored.
  - ScriptedTarget: new opt `unit_handler: fn conn_id, seq, mr -> {reply_conn_id, mr_response} | :no_reply end` — a `handle_frame` clause for `:send_unit_data` that unwraps interface prefix + CPF, calls the fun, and replies with CPF `[{:connected_address, reply_conn_id}, {:connected_data, <<seq::16-little, response>>}]` echoing the sequence (uses `send_reply/4` so `split_replies`/`reply_prefix` still apply).

- [ ] **Step 1: Extend ScriptedTarget**

Add to `test/support/scripted_target.ex` (before the catch-all/nop clauses; the
`opts` are already threaded into `handle_frame/5`):

```elixir
  defp handle_frame(socket, %Encap{command: :send_unit_data} = frame, _handler, agent, opts) do
    case opts[:unit_handler] do
      nil ->
        :ok

      unit_handler ->
        {:ok, cpf} = Encap.unwrap_cpf(frame)
        {:ok, items} = CPF.decode(cpf)
        [{:connected_address, conn_id}] = for {:connected_address, _} = i <- items, do: i

        [{:connected_data, <<seq::16-little, mr::binary>>}] =
          for {:connected_data, _} = i <- items, do: i

        case unit_handler.(conn_id, seq, mr) do
          :no_reply ->
            :ok

          {reply_conn_id, response} ->
            reply_cpf =
              CPF.encode([
                {:connected_address, reply_conn_id},
                {:connected_data, <<seq::16-little, response::binary>>}
              ])

            reply = %Encap{
              Encap.send_unit_data(@session_handle, reply_cpf)
              | sender_context: frame.sender_context
            }

            send_reply(socket, Encap.encode(reply), opts, agent)
        end
    end
  end
```

- [ ] **Step 2: Write the failing tests (append to `Eipex.ScannerConnectedTest`)**

```elixir
  defp connected_pair(unit_handler) do
    target =
      ScriptedTarget.start(fo_success_handler(o2t_id: 0x0102_0304),
        unit_handler: unit_handler
      )

    pid = start_scanner(target)
    {:ok, conn} = Scanner.forward_open(pid)
    {target, pid, conn}
  end

  test "connected requests ride SendUnitData with incrementing sequence counts" do
    test_pid = self()
    {:ok, t2o_holder} = Agent.start_link(fn -> nil end)

    fo_handler = fn mr ->
      {:ok, %{service: service, data: data}} = MessageRouter.decode_request(mr)
      {:ok, fo} = CM.decode_forward_open(service, data)
      Agent.update(t2o_holder, fn _ -> fo.t2o_connection_id end)

      reply = %CM.ForwardOpenReply{
        o2t_connection_id: 0x0102_0304,
        t2o_connection_id: fo.t2o_connection_id,
        connection_serial: fo.connection_serial,
        originator_vendor_id: fo.originator_vendor_id,
        originator_serial: fo.originator_serial,
        o2t_api: fo.o2t_rpi, t2o_api: fo.t2o_rpi, application_reply: <<>>
      }

      MessageRouter.encode_response(service, 0x00, data: CM.encode_forward_open_reply(reply))
    end

    unit_handler = fn conn_id, seq, mr ->
      send(test_pid, {:unit, conn_id, seq})
      {:ok, %{service: 0x0E}} = MessageRouter.decode_request(mr)
      {Agent.get(t2o_holder, & &1), MessageRouter.encode_response(0x0E, 0x00, data: <<seq::16-little>>)}
    end

    target = ScriptedTarget.start(fo_handler, unit_handler: unit_handler)
    pid = start_scanner(target)
    {:ok, _conn} = Scanner.forward_open(pid)

    assert {:ok, %{status_name: :success, data: <<1::16-little>>}} =
             Scanner.generic_message(pid,
               service: 0x0E, class: 1, instance: 1, attribute: 1, connected: true)

    assert_receive {:unit, 0x0102_0304, 1}

    assert {:ok, %{data: <<2::16-little>>}} =
             Scanner.generic_message(pid,
               service: 0x0E, class: 1, instance: 1, attribute: 1, connected: true)

    assert_receive {:unit, 0x0102_0304, 2}
    Scanner.close(pid)
  end

  test "connected request without a connection errors cleanly" do
    target = ScriptedTarget.start(fo_success_handler())
    pid = start_scanner(target)

    assert {:error, :no_connection} =
             Scanner.generic_message(pid,
               service: 0x0E, class: 1, instance: 1, attribute: 1, connected: true)

    Scanner.close(pid)
  end

  test "mismatched connection ids in replies are ignored until timeout" do
    unit_handler = fn _conn_id, _seq, mr ->
      {:ok, %{service: service}} = MessageRouter.decode_request(mr)
      {0xDEAD_BEEF, MessageRouter.encode_response(service, 0x00)}
    end

    target = ScriptedTarget.start(fo_success_handler(), unit_handler: unit_handler)
    pid = start_scanner(target)
    {:ok, _conn} = Scanner.forward_open(pid)

    assert {:error, :timeout} =
             Scanner.generic_message(pid,
               service: 0x0E, class: 1, instance: 1, attribute: 1,
               connected: true, timeout: 150)

    Scanner.close(pid)
  end
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_connected_test.exs`
Expected: the three new tests FAIL (`connected: true` currently ignored → request
goes UCMM → ScriptedTarget's rr handler gets it / no_connection error missing).

- [ ] **Step 4: Implement in `lib/eipex/scanner.ex`**

In `handle_call({:request, opts}, from, state)` — route connected requests before
the existing build:

```elixir
  def handle_call({:request, opts}, from, state) do
    if Keyword.get(opts, :connected, false) do
      connected_request(opts, from, state)
    else
      ... existing body unchanged ...
    end
  rescue
    ...
  end

  defp connected_request(_opts, _from, %State{connection: nil} = state) do
    {:reply, {:error, :no_connection}, state}
  end

  defp connected_request(opts, from, state) do
    with {:ok, service} <- Keyword.fetch(opts, :service),
         {:ok, path} <- request_path(opts) do
      mr = MessageRouter.encode_request(service, path, Keyword.get(opts, :data, <<>>))
      timeout = Keyword.get(opts, :timeout, state.timeout)
      dispatch_request(state, from, {:unit, mr}, timeout, :connected)
    else
      :error -> {:reply, {:error, :missing_service}, state}
      {:error, _} = error -> {:reply, error, state}
    end
  end
```

`send_request/5` branches on the payload shape (`{:unit, mr}` vs plain binary).
The nil-connection guard covers a queued connected request whose connection was
closed (forward_close) before its turn to send:

```elixir
  defp send_request(%State{connection: nil} = state, from, {:unit, _mr}, _timeout, :connected) do
    GenServer.reply(from, {:error, :no_connection})
    next_request(state)
  end

  defp send_request(state, from, {:unit, mr}, timeout, :connected) do
    conn = state.connection
    seq = conn.seq

    cpf =
      CPF.encode([
        {:connected_address, conn.o2t_connection_id},
        {:connected_data, <<seq::16-little, mr::binary>>}
      ])

    frame = Encap.send_unit_data(state.session_handle, cpf)

    case :gen_tcp.send(state.socket, Encap.encode(frame)) do
      :ok ->
        timer = Process.send_after(self(), {:request_timeout, {:unit, seq}}, timeout)
        next_seq = if seq >= 0xFFFF, do: 1, else: seq + 1

        {:ok,
         %{state |
           pending: {from, {:unit, seq}, timer, {:connected, conn.t2o_connection_id, seq}},
           connection: %{conn | seq: next_seq}}}

      {:error, _} ->
        GenServer.reply(from, {:error, :connection_lost})
        {:lost, state}
    end
  end

  defp send_request(state, from, mr, timeout, kind) when is_binary(mr) do
    ... existing UCMM body, storing pending {from, context, timer, kind} ...
  end
```

(The pending "context" slot holds `{:unit, seq}` for connected requests — the
timeout message uses it, and the UCMM `send_rr_data` handle_frame clause can
never match it since real sender contexts are 8-byte binaries.)

New `handle_frame` clause (place BEFORE the catch-all, alongside the rr clause):

```elixir
  defp handle_frame(
         %State{pending: {from, _ref, timer, {:connected, t2o_id, seq}}} = state,
         %Encap{command: :send_unit_data, status: 0} = frame
       ) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [{:connected_address, ^t2o_id}] <-
           (for {:connected_address, _} = i <- items, do: i),
         [{:connected_data, <<^seq::16-little, mr::binary>>}] <-
           (for {:connected_data, _} = i <- items, do: i),
         {:ok, response} <- MessageRouter.decode_response(mr) do
      Process.cancel_timer(timer)
      GenServer.reply(from, {:ok, response})
      next_request(%{state | pending: nil})
    else
      _mismatch -> {:ok, state}
    end
  end
```

The forward_close settle path (Task 2) must ALSO clear `connection:` when the
underlying session drops (`fail_callers` already replies; add `connection: nil`
to the state reset there is unnecessary — the process stops). No change needed.

- [ ] **Step 5: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_connected_test.exs`
Expected: PASS, 8 tests. Full `mix test` green.

- [ ] **Step 6: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner connected requests over SendUnitData with sequence counts`

```bash
mix format && git add -A && git commit -m "feat: scanner connected messaging"
```

---

### Task 4: Adapter ConnectionTable + Forward Open/Close handling

**Files:**
- Create: `lib/eipex/adapter/connection_table.ex`
- Modify: `lib/eipex/adapter/config.ex` (+ `connections` field), `lib/eipex/adapter/adapter.ex` (start table, `max_connections` opt), `lib/eipex/adapter/message_router.ex` (ctx gains `session` + `connections`), `lib/eipex/adapter/object/connection_manager.ex` (real FO/LFO/FC)
- Test: `test/eipex/adapter/connection_table_test.exs`, `test/eipex/adapter/connected_objects_test.exs`

**Interfaces:**
- Consumes: `CM.decode_forward_open/2`, `CM.encode_forward_open_reply/1`, `CM.decode_forward_close/1`, Task 1 codecs, `Path.decode/1`.
- Produces:
  - `Eipex.Adapter.ConnectionTable.start_link(max: pos_integer) :: {:ok, pid}`
  - `register(table, triad, info, session_pid) :: {:ok, o2t_id} | {:error, :duplicate | :capacity}` — `triad :: {serial, vendor, orig_serial}`; `info :: %{t2o_connection_id: id}`; assigns a unique nonzero 32-bit `o2t_id`; MONITORS `session_pid` and auto-removes that session's connections on DOWN.
  - `unregister(table, triad) :: {:ok, removed_info} | {:error, :not_found}`
  - `lookup_o2t(table, o2t_id) :: {:ok, %{triad, t2o_connection_id, session: pid}} | :error`
  - `count(table) :: non_neg_integer`
  - `%Config{connections: pid}`; adapter opt `max_connections` (default 8).
  - `MessageRouter.dispatch/2` ctx gains `session: self()` and `connections: config.connections`.
  - `Object.ConnectionManager.handle_service/5` for 0x54/0x5B: decode (malformed → 0x13); transport class ≠ 3 → `{:error, 0x01, [0x0103]}`; connection path (after stripping leading `{:port, _, _}` segments) ≠ `[class: 0x02, instance: 0x01]` → `{:error, 0x01, [0x0315]}`; register in table (duplicate → `[0x0100]`, capacity → `[0x0113]`); success → reply with `CM.encode_forward_open_reply` (o2t = assigned, t2o = echoed, APIs = requested RPIs, empty app reply). 0x4E: decode FC (malformed → 0x13), unregister (not found → `{:error, 0x01, [0x0107]}`), success → `CM.encode_forward_close_reply(triad)`.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/connection_table_test.exs`:

```elixir
defmodule Eipex.Adapter.ConnectionTableTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.ConnectionTable

  @triad {1, 0x004D, 0xDEAD_0001}

  test "registers, looks up and unregisters connections" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    assert {:ok, o2t} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 7}, self())
    assert o2t != 0
    assert ConnectionTable.count(table) == 1

    assert {:ok, %{triad: @triad, t2o_connection_id: 7, session: session}} =
             ConnectionTable.lookup_o2t(table, o2t)

    assert session == self()

    assert {:ok, _info} = ConnectionTable.unregister(table, @triad)
    assert :error = ConnectionTable.lookup_o2t(table, o2t)
    assert {:error, :not_found} = ConnectionTable.unregister(table, @triad)
  end

  test "rejects duplicate triads and enforces capacity" do
    {:ok, table} = ConnectionTable.start_link(max: 1)

    assert {:ok, _} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 1}, self())
    assert {:error, :duplicate} =
             ConnectionTable.register(table, @triad, %{t2o_connection_id: 2}, self())

    other = {2, 0x004D, 0xDEAD_0001}
    assert {:error, :capacity} =
             ConnectionTable.register(table, other, %{t2o_connection_id: 3}, self())
  end

  test "a dead session releases its connections" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    session =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    {:ok, o2t} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 1}, session)
    send(session, :stop)
    Process.sleep(50)

    assert :error = ConnectionTable.lookup_o2t(table, o2t)
    assert ConnectionTable.count(table) == 0
    # triad reusable after cleanup
    assert {:ok, _} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 2}, self())
  end
end
```

`test/eipex/adapter/connected_objects_test.exs` (dispatch-level, no sockets):

```elixir
defmodule Eipex.Adapter.ConnectedObjectsTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{Config, ConnectionTable, MessageRouter}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  defp config(max \\ 8) do
    {:ok, table} = ConnectionTable.start_link(max: max)

    %Config{
      identity: nil,
      handler: Eipex.Adapter.Handler.Default,
      connections: table,
      objects: %{0x06 => Eipex.Adapter.Object.ConnectionManager}
    }
  end

  defp forward_open(overrides \\ []) do
    base = %CM.ForwardOpen{
      priority_time_tick: 0x0A, timeout_ticks: 10,
      o2t_connection_id: 0, t2o_connection_id: 0x1122_3344,
      connection_serial: 1, originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001, timeout_multiplier: 1,
      o2t_rpi: 10_000_000,
      o2t_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                    size_type: :variable, size: 500},
      t2o_rpi: 10_000_000,
      t2o_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                    size_type: :variable, size: 500},
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(class: 0x02, instance: 0x01)
    }

    struct!(base, overrides)
  end

  defp dispatch(config, request) do
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "forward open registers a class 3 connection and replies with assigned ids" do
    cfg = config()
    request = CM.encode_forward_open(forward_open(), :standard)

    response = dispatch(cfg, request)
    assert response.status_name == :success

    {:ok, reply} = CM.decode_forward_open_reply(response.data)
    assert reply.t2o_connection_id == 0x1122_3344
    assert reply.o2t_connection_id != 0
    assert reply.o2t_api == 10_000_000

    assert {:ok, %{t2o_connection_id: 0x1122_3344}} =
             ConnectionTable.lookup_o2t(cfg.connections, reply.o2t_connection_id)
  end

  test "large forward open works too" do
    cfg = config()

    fo =
      forward_open(
        o2t_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                      size_type: :variable, size: 4002},
        t2o_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                      size_type: :variable, size: 4002}
      )

    response = dispatch(cfg, CM.encode_forward_open(fo, :large))
    assert response.status_name == :success
  end

  test "transport classes other than 3 answer 0x0103" do
    cfg = config()

    fo = forward_open(transport: %{direction: :server, trigger: :cyclic, class: 1})
    response = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    assert response.status_name == :connection_failure
    assert response.extended == [0x0103]
  end

  test "connection paths not addressing the message router answer 0x0315" do
    cfg = config()

    fo = forward_open(connection_path: Path.encode(class: 0x04, instance: 100))
    response = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    assert response.extended == [0x0315]
  end

  test "a leading port segment is accepted (routed forward open)" do
    cfg = config()

    fo = forward_open(connection_path: Path.encode([{:port, 1, 0}, {:class, 0x02}, {:instance, 0x01}]))
    response = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    assert response.status_name == :success
  end

  test "duplicate triads and capacity are rejected" do
    cfg = config(1)
    request = CM.encode_forward_open(forward_open(), :standard)

    assert %{status_name: :success} = dispatch(cfg, request)
    assert %{extended: [0x0100]} = dispatch(cfg, request)

    other = CM.encode_forward_open(forward_open(connection_serial: 2), :standard)
    assert %{extended: [0x0113]} = dispatch(cfg, other)
  end

  test "forward close unregisters; unknown triads answer 0x0107" do
    cfg = config()
    fo = forward_open()

    %{status_name: :success} = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    triad = %{connection_serial: 1, originator_vendor_id: 0x004D,
              originator_serial: 0xDEAD_0001}

    close = CM.encode_forward_close(triad, fo.connection_path, [])
    response = dispatch(cfg, close)
    assert response.status_name == :success

    assert {:ok, %{connection_serial: 1}} = CM.decode_forward_close_reply(response.data)
    assert %{extended: [0x0107]} = dispatch(cfg, close)
  end

  test "malformed forward open payloads answer 0x13" do
    cfg = config()
    request = MR.encode_request(0x54, [class: 0x06, instance: 1], <<1, 2, 3>>)
    assert %{status_name: :not_enough_data} = dispatch(cfg, request)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/connection_table_test.exs test/eipex/adapter/connected_objects_test.exs`
Expected: FAIL — `ConnectionTable` undefined; FO answers 0x08 (Phase 3 placeholder).

- [ ] **Step 3: Implement**

`lib/eipex/adapter/connection_table.ex`:

```elixir
defmodule Eipex.Adapter.ConnectionTable do
  @moduledoc """
  Registry of class 3 connections: triad -> connection info, with capacity
  enforcement and automatic cleanup when the owning TCP session dies
  (monitor-based). One per adapter.
  """

  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  def register(table, triad, info, session_pid),
    do: GenServer.call(table, {:register, triad, info, session_pid})

  def unregister(table, triad), do: GenServer.call(table, {:unregister, triad})

  def lookup_o2t(table, o2t_id), do: GenServer.call(table, {:lookup_o2t, o2t_id})

  def count(table), do: GenServer.call(table, :count)

  @impl true
  def init(opts) do
    {:ok,
     %{max: Keyword.fetch!(opts, :max), by_triad: %{}, by_o2t: %{},
       monitors: %{}, next_id: 1}}
  end

  @impl true
  def handle_call({:register, triad, info, session_pid}, _from, state) do
    cond do
      Map.has_key?(state.by_triad, triad) ->
        {:reply, {:error, :duplicate}, state}

      map_size(state.by_triad) >= state.max ->
        {:reply, {:error, :capacity}, state}

      true ->
        o2t_id = state.next_id
        record = Map.merge(info, %{triad: triad, session: session_pid, o2t_id: o2t_id})
        monitors = Map.put_new_lazy(state.monitors, session_pid, fn ->
          Process.monitor(session_pid)
        end)

        {:reply, {:ok, o2t_id},
         %{state |
           by_triad: Map.put(state.by_triad, triad, record),
           by_o2t: Map.put(state.by_o2t, o2t_id, record),
           monitors: monitors,
           next_id: state.next_id + 1}}
    end
  end

  def handle_call({:unregister, triad}, _from, state) do
    case Map.pop(state.by_triad, triad) do
      {nil, _} ->
        {:reply, {:error, :not_found}, state}

      {record, by_triad} ->
        {:reply, {:ok, record},
         %{state | by_triad: by_triad, by_o2t: Map.delete(state.by_o2t, record.o2t_id)}}
    end
  end

  def handle_call({:lookup_o2t, o2t_id}, _from, state) do
    case state.by_o2t do
      %{^o2t_id => record} -> {:reply, {:ok, record}, state}
      _ -> {:reply, :error, state}
    end
  end

  def handle_call(:count, _from, state), do: {:reply, map_size(state.by_triad), state}

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    {dead, by_triad} =
      Enum.split_with(state.by_triad, fn {_triad, record} -> record.session == pid end)

    by_o2t = Enum.reduce(dead, state.by_o2t, fn {_t, r}, acc -> Map.delete(acc, r.o2t_id) end)

    {:noreply,
     %{state |
       by_triad: Map.new(by_triad),
       by_o2t: by_o2t,
       monitors: Map.delete(state.monitors, pid)}}
  end

  def handle_info(_message, state), do: {:noreply, state}
end
```

`Config`: add `connections: nil` to the defstruct. `Adapter.init/1`: start it
right after the assembly store and thread it into the config:

```elixir
         {:ok, connections} <-
           Eipex.Adapter.ConnectionTable.start_link(
             max: Keyword.get(opts, :max_connections, 8)
           ),
```

and `connections: connections` in the `%Config{}`.

`MessageRouter.invoke/6` ctx becomes:

```elixir
        ctx = %{config: config, store: config.store, handler: config.handler,
                session: self(), connections: config.connections}
```

`Object.ConnectionManager` — replace the 0x54/0x5B/0x4E placeholder clauses:

```elixir
  def handle_service(service, 1, [], data, ctx)
      when service in [@forward_open, @large_forward_open] do
    case CM.decode_forward_open(service, data) do
      {:ok, fo} -> open_connection(fo, ctx)
      {:error, _} -> {:error, 0x13, []}
    end
  end

  def handle_service(@forward_close, 1, [], data, ctx) do
    case CM.decode_forward_close(data) do
      {:ok, fc} ->
        triad = {fc.connection_serial, fc.originator_vendor_id, fc.originator_serial}

        case Eipex.Adapter.ConnectionTable.unregister(ctx.connections, triad) do
          {:ok, _record} ->
            {:reply,
             CM.encode_forward_close_reply(%{
               connection_serial: fc.connection_serial,
               originator_vendor_id: fc.originator_vendor_id,
               originator_serial: fc.originator_serial
             })}

          {:error, :not_found} ->
            {:error, 0x01, [0x0107]}
        end

      {:error, _} ->
        {:error, 0x13, []}
    end
  end

  defp open_connection(fo, ctx) do
    with :ok <- validate_transport(fo),
         :ok <- validate_path(fo) do
      triad = {fo.connection_serial, fo.originator_vendor_id, fo.originator_serial}
      info = %{t2o_connection_id: fo.t2o_connection_id}

      case Eipex.Adapter.ConnectionTable.register(ctx.connections, triad, info, ctx.session) do
        {:ok, o2t_id} ->
          {:reply,
           CM.encode_forward_open_reply(%CM.ForwardOpenReply{
             o2t_connection_id: o2t_id,
             t2o_connection_id: fo.t2o_connection_id,
             connection_serial: fo.connection_serial,
             originator_vendor_id: fo.originator_vendor_id,
             originator_serial: fo.originator_serial,
             o2t_api: fo.o2t_rpi,
             t2o_api: fo.t2o_rpi,
             application_reply: <<>>
           })}

        {:error, :duplicate} -> {:error, 0x01, [0x0100]}
        {:error, :capacity} -> {:error, 0x01, [0x0113]}
      end
    end
  end

  defp validate_transport(%{transport: %{class: 3}}), do: :ok
  defp validate_transport(_fo), do: {:error, 0x01, [0x0103]}

  defp validate_path(fo) do
    case Eipex.CIP.Path.decode(fo.connection_path) do
      {:ok, segments} ->
        segments
        |> Enum.drop_while(&match?({:port, _, _}, &1))
        |> case do
          [class: 0x02, instance: 0x01] -> :ok
          _ -> {:error, 0x01, [0x0315]}
        end

      {:error, _} ->
        {:error, 0x01, [0x0315]}
    end
  end
```

(The `with` propagates the `{:error, status, ext}` tuples unchanged — they are
already the behaviour's error shape.)

ALSO update the Phase 3 test that pinned the placeholder behavior:
in `test/eipex/adapter/object/network_objects_test.exs`, REPLACE the test
"forward open family answers service_not_supported until phase 4" with:

```elixir
  test "forward open family with malformed payloads answers not_enough_data" do
    cfg = config()

    for service <- [0x54, 0x5B, 0x4E] do
      assert %{status_name: :not_enough_data} =
               roundtrip(cfg, service, [class: 0x06, instance: 1], <<0>>)
    end
  end
```

(That config has `connections: nil`, which is fine — the malformed payload is
rejected before the table is touched. Real FO/FC behavior is covered by the new
`connected_objects_test.exs`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/`
Expected: PASS (11 new + all Phase 3 adapter tests). Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter class 3 Forward Open/Close with connection table and capacity`

```bash
mix format && git add -A && git commit -m "feat: adapter forward open handling"
```

---

### Task 5: Adapter SendUnitData serving

**Files:**
- Modify: `lib/eipex/adapter/session_handler.ex`
- Test: `test/eipex/adapter/connected_session_test.exs` (new, raw gen_tcp)

**Interfaces:**
- Consumes: `ConnectionTable.lookup_o2t/2` (Task 4), `MessageRouter.dispatch/2`, CPF connected items.
- Produces: a `handle_frame` clause for `%Encap{command: :send_unit_data}` placed BEFORE the catch-all:
  - No registered session or handle mismatch → echo status 0x0064.
  - Malformed CPF / missing connected items / connected data shorter than 2 bytes → echo status 0x0003.
  - `{:connected_address, id}` not in the table, or owned by a DIFFERENT session pid → DROP silently (no reply is routable; the catch-all must NOT answer 0x0001 for these).
  - Known connection, new sequence → dispatch the MR request, reply SendUnitData with CPF `[{:connected_address, t2o_id}, {:connected_data, <<seq::16-little, response>>}]`, cache `{seq, reply_frame}` per o2t id in session state (`conn_replies` map).
  - Same sequence as cached (retransmission) → resend the cached reply WITHOUT re-dispatching (no double side effects).
- Session state gains `conn_replies: %{}`.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/connected_session_test.exs`:

```elixir
defmodule Eipex.Adapter.ConnectedSessionTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  defp start_adapter(extra \\ []) do
    {:ok, pid} =
      Eipex.Adapter.start_link(
        [identity: @identity,
         assemblies: [output: [instance: 150, size: 4]], port: 0] ++ extra
      )

    {:ok, port} = Eipex.Adapter.port(pid)
    {pid, port}
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
    %Encap{command: :register_session, session_handle: handle} = recv_frame(socket)
    handle
  end

  defp open_connection(socket, handle, serial \\ 1) do
    fo = %CM.ForwardOpen{
      priority_time_tick: 0x0A, timeout_ticks: 10,
      o2t_connection_id: 0, t2o_connection_id: 0x1122_3344,
      connection_serial: serial, originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001, timeout_multiplier: 1,
      o2t_rpi: 10_000_000,
      o2t_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                    size_type: :variable, size: 500},
      t2o_rpi: 10_000_000,
      t2o_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                    size_type: :variable, size: 500},
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(class: 0x02, instance: 0x01)
    }

    cpf = CPF.encode([:null_address,
                      {:unconnected_data, CM.encode_forward_open(fo, :standard)}])
    send_frame(socket, Encap.send_rr_data(handle, cpf))

    reply = recv_frame(socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)
    [{:unconnected_data, mr}] = for {:unconnected_data, _} = i <- items, do: i
    {:ok, %{status_name: :success, data: data}} = MR.decode_response(mr)
    {:ok, fo_reply} = CM.decode_forward_open_reply(data)
    fo_reply.o2t_connection_id
  end

  defp unit_frame(handle, conn_id, seq, mr) do
    cpf = CPF.encode([{:connected_address, conn_id},
                      {:connected_data, <<seq::16-little, mr::binary>>}])
    Encap.send_unit_data(handle, cpf)
  end

  defp unit_response(frame) do
    {:ok, cpf} = Encap.unwrap_cpf(frame)
    {:ok, items} = CPF.decode(cpf)
    [{:connected_address, id}] = for {:connected_address, _} = i <- items, do: i

    [{:connected_data, <<seq::16-little, mr::binary>>}] =
      for {:connected_data, _} = i <- items, do: i

    {:ok, response} = MR.decode_response(mr)
    {id, seq, response}
  end

  test "serves connected requests with sequence echo on the t2o id" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)
    o2t = open_connection(socket, handle)

    mr = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    send_frame(socket, unit_frame(handle, o2t, 1, mr))

    {id, seq, response} = unit_response(recv_frame(socket))
    assert id == 0x1122_3344
    assert seq == 1
    assert response.status_name == :success
    assert response.data == <<0x4D, 0x00>>
  end

  test "retransmissions with the same sequence resend the cached reply without side effects" do
    {pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)
    o2t = open_connection(socket, handle)

    write = MR.encode_request(0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2, 3, 4>>)
    send_frame(socket, unit_frame(handle, o2t, 5, write))
    {_id, 5, %{status_name: :success}} = unit_response(recv_frame(socket))

    # mutate the assembly out-of-band, then retransmit seq 5: the cached success
    # reply must come back and the store must NOT be overwritten again
    :ok = Eipex.Adapter.write_assembly(pid, 150, <<9, 9, 9, 9>>)
    send_frame(socket, unit_frame(handle, o2t, 5, write))
    {_id, 5, %{status_name: :success}} = unit_response(recv_frame(socket))

    assert {:ok, <<9, 9, 9, 9>>} = Eipex.Adapter.read_assembly(pid, 150)
  end

  test "unknown connection ids are dropped silently" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)
    _o2t = open_connection(socket, handle)

    mr = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    send_frame(socket, unit_frame(handle, 0xDEAD_BEEF, 1, mr))

    assert {:error, :timeout} = :gen_tcp.recv(socket, 0, 300)
  end

  test "send_unit_data with a wrong session handle answers 0x64" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)

    send_frame(socket, Encap.send_unit_data(0xBAD, <<>>))
    assert %Encap{command: :send_unit_data, status: 0x0064} = recv_frame(socket)
  end

  test "malformed connected payloads answer 0x0003" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)

    send_frame(socket, Encap.send_unit_data(handle, <<0xFF>>))
    assert %Encap{command: :send_unit_data, status: 0x0003} = recv_frame(socket)
  end

  test "a connection opened on one session is not servable from another" do
    {_pid, port} = start_adapter()
    socket1 = connect(port)
    handle1 = register(socket1)
    o2t = open_connection(socket1, handle1)

    socket2 = connect(port)
    handle2 = register(socket2)

    mr = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    send_frame(socket2, unit_frame(handle2, o2t, 1, mr))
    assert {:error, :timeout} = :gen_tcp.recv(socket2, 0, 300)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/connected_session_test.exs`
Expected: FAIL — SendUnitData currently hits the Phase 3 catch-all (echo 0x0001),
so the first test gets a 0x0001 echo instead of a connected reply.

- [ ] **Step 3: Implement in `lib/eipex/adapter/session_handler.ex`**

Add `conn_replies: %{}` to the init state map. Insert BEFORE the catch-all clause:

```elixir
  defp handle_frame(state, %Encap{command: :send_unit_data, session_handle: handle} = frame) do
    cond do
      is_nil(state.session_handle) or handle != state.session_handle ->
        reply(state, %Encap{frame | status: 0x0064, data: <<>>})
        state

      true ->
        case unit_payload(frame) do
          {:ok, conn_id, seq, mr} -> serve_connected(state, conn_id, seq, mr)
          {:error, _} ->
            reply(state, %Encap{frame | status: 0x0003, data: <<>>})
            state
        end
    end
  end

  defp unit_payload(frame) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [{:connected_address, conn_id}] <-
           (for {:connected_address, _} = i <- items, do: i),
         [{:connected_data, <<seq::16-little, mr::binary>>}] <-
           (for {:connected_data, _} = i <- items, do: i) do
      {:ok, conn_id, seq, mr}
    else
      _ -> {:error, :malformed}
    end
  end

  defp serve_connected(state, conn_id, seq, mr) do
    case Eipex.Adapter.ConnectionTable.lookup_o2t(state.config.connections, conn_id) do
      {:ok, %{session: session, t2o_connection_id: t2o_id}} when session == self() ->
        case state.conn_replies do
          %{^conn_id => {^seq, cached}} ->
            reply(state, cached)
            state

          _ ->
            response = MessageRouter.dispatch(state.config, mr)

            reply_frame = %Encap{
              Encap.send_unit_data(
                state.session_handle,
                CPF.encode([
                  {:connected_address, t2o_id},
                  {:connected_data, <<seq::16-little, response::binary>>}
                ])
              )
              | sender_context: <<0::64>>
            }

            reply(state, reply_frame)
            %{state | conn_replies: Map.put(state.conn_replies, conn_id, {seq, reply_frame})}
        end

      _unknown_or_foreign ->
        # no reply is routable for an unknown/foreign connection: drop
        state
    end
  end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/connected_session_test.exs`
Expected: PASS, 6 tests. Full `mix test` green (the Phase 3 session test that
expected SendUnitData to echo 0x0001 does not exist — unknown commands still do).

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter serves connected requests with sequence dedup and reply caching`

```bash
mix format && git add -A && git commit -m "feat: adapter connected messaging"
```

---

### Task 6: Connected loopback + pycomm3 connected interop

**Files:**
- Test: `test/eipex/adapter/connected_loopback_test.exs` (new)
- Modify: `interop/pycomm3/check_adapter.py` (+ connected read), `test/interop/pycomm3_test.exs` (+2 assertions)

**Interfaces:**
- Consumes: everything above; the REAL scanner and adapter.
- Produces: end-to-end proof both roles interoperate over class 3, plus reference validation via pycomm3's `connected=True` path (its `@with_forward_open` opens a real CIP connection and `driver.close()` sends Forward Close).

- [ ] **Step 1: Write the loopback tests**

`test/eipex/adapter/connected_loopback_test.exs`:

```elixir
defmodule Eipex.Adapter.ConnectedLoopbackTest do
  use ExUnit.Case

  alias Eipex.Scanner

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  defp start_pair(adapter_extra \\ [], scanner_extra \\ []) do
    {:ok, adapter} =
      Eipex.Adapter.start_link(
        [identity: @identity,
         assemblies: [output: [instance: 150, size: 4]], port: 0] ++ adapter_extra
      )

    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner} =
      Scanner.start_link(
        [host: {127, 0, 0, 1}, port: port,
         vendor_id: 0x004D, serial_number: 0xDEAD_0001] ++ scanner_extra
      )

    {adapter, scanner}
  end

  test "full connected round trip: open, request, request, close, reopen" do
    {_adapter, scanner} = start_pair()

    assert {:ok, conn} = Scanner.forward_open(scanner)
    assert conn.variant == :large

    assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
             Scanner.generic_message(scanner,
               service: 0x0E, class: 1, instance: 1, attribute: 1, connected: true)

    assert :ok =
             Scanner.set_attribute(scanner, 0x04, 150, 3, <<7, 7, 7, 7>>, connected: true)

    assert {:ok, <<7, 7, 7, 7>>} =
             Scanner.get_attribute(scanner, 0x04, 150, 3, connected: true)

    assert :ok = Scanner.forward_close(scanner)

    assert {:error, :no_connection} =
             Scanner.generic_message(scanner,
               service: 0x0E, class: 1, instance: 1, attribute: 1, connected: true)

    assert {:ok, _} = Scanner.forward_open(scanner)
    Scanner.close(scanner)
  end

  test "duplicate triads across sessions are rejected" do
    {adapter, scanner1} = start_pair()
    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner2} =
      Scanner.start_link(host: {127, 0, 0, 1}, port: port,
                         vendor_id: 0x004D, serial_number: 0xDEAD_0001)

    {:ok, _} = Scanner.forward_open(scanner1)

    # same vendor/serial and both serial counters start at 1 -> same triad;
    # the large attempt AND its standard fallback both collide
    assert {:error, {:cip, :connection_failure, [0x0100]}} =
             Scanner.forward_open(scanner2, variant: :standard)

    Scanner.close(scanner1)
    Scanner.close(scanner2)
  end

  test "closing the session releases connections in the adapter" do
    {adapter, scanner1} = start_pair()
    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, _} = Scanner.forward_open(scanner1)
    Scanner.close(scanner1)
    Process.sleep(100)

    {:ok, scanner2} =
      Scanner.start_link(host: {127, 0, 0, 1}, port: port,
                         vendor_id: 0x004D, serial_number: 0xDEAD_0001)

    # same triad now free again
    assert {:ok, _} = Scanner.forward_open(scanner2, variant: :standard)
    Scanner.close(scanner2)
  end

  test "capacity is enforced" do
    {adapter, scanner1} = start_pair(max_connections: 1)
    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner2} =
      Scanner.start_link(host: {127, 0, 0, 1}, port: port,
                         vendor_id: 0x004D, serial_number: 0xBEEF_0002)

    {:ok, _} = Scanner.forward_open(scanner1)

    assert {:error, {:cip, :connection_failure, [0x0113]}} =
             Scanner.forward_open(scanner2, variant: :standard)

    Scanner.close(scanner1)
    Scanner.close(scanner2)
  end

  test "class 1 forward opens are refused with 0x0103 until phase 5" do
    {_adapter, scanner} = start_pair()

    fo = %Eipex.CIP.ConnectionManager.ForwardOpen{
      priority_time_tick: 0x0A, timeout_ticks: 10,
      o2t_connection_id: 0, t2o_connection_id: 0x0BAD_CAFE,
      connection_serial: 99, originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001, timeout_multiplier: 1,
      o2t_rpi: 10_000, o2t_params: %{owner: :exclusive, type: :point_to_point,
                                     priority: :low, size_type: :fixed, size: 4},
      t2o_rpi: 10_000, t2o_params: %{owner: :exclusive, type: :point_to_point,
                                     priority: :low, size_type: :fixed, size: 4},
      transport: %{direction: :server, trigger: :cyclic, class: 1},
      connection_path: Eipex.CIP.Path.encode(class: 0x02, instance: 0x01)
    }

    request = Eipex.CIP.ConnectionManager.encode_forward_open(fo, :standard)
    {:ok, %{service: 0x54, path: path, data: data}} =
      Eipex.CIP.MessageRouter.decode_request(request)

    {:ok, [class: class, instance: instance]} = Eipex.CIP.Path.decode(path)

    assert {:ok, %{status_name: :connection_failure, extended: [0x0103]}} =
             Scanner.generic_message(scanner,
               service: 0x54, class: class, instance: instance, data: data)

    Scanner.close(scanner)
  end
end
```

Note: `get_attribute`/`set_attribute`/`get_attributes_all` pass their `opts`
through to `generic_message`, so `connected: true` already flows — no helper
changes needed (verify while implementing; if the helpers drop unknown opts,
thread them).

- [ ] **Step 2: Run, fix, pass**

Run: `mix test test/eipex/adapter/connected_loopback_test.exs`
Expected: PASS if Tasks 2-5 are correct — treat failures as integration bugs
(most likely: seq wrap, close-session cleanup timing, or helper opt threading).
Full `mix test` green.

- [ ] **Step 3: Extend the pycomm3 script and interop test**

In `interop/pycomm3/check_adapter.py`, after the `unknown_class_errors` block:

```python
connected = driver.generic_message(
    service=Services.get_attribute_single, class_code=1, instance=1,
    attribute=1, connected=True, name="connected_read")
results["connected_ok"] = connected.error is None
results["connected_vendor"] = list(connected.value) if connected.value else None
```

(`connected=True` makes pycomm3 run its own Forward Open first — large with
standard fallback — and `driver.close()` at the end sends Forward Close.)

In `test/interop/pycomm3_test.exs` add:

```elixir
    assert results["connected_ok"]
    assert results["connected_vendor"] == [0x4D, 0x00]
```

- [ ] **Step 4: Run the interop for real**

```bash
mix test --include interop test/interop/pycomm3_test.exs
```

Expected: 1 test, 0 failures. If pycomm3's Forward Open shape trips a validation
(e.g. a connection path our validator rejects), capture the exact FO fields from
the adapter side, adjust the VALIDATOR only if pycomm3's shape is legitimate per
spec (document the decision in your report either way). Confirm hermetic
`mix test` still excludes interop.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Connected loopback tests and pycomm3 connected-messaging interop`

```bash
mix format && git add -A && git commit -m "test: connected loopback and interop"
```

---

### Task 7: Deferred mini-fixes (narrowed rescue, RegisterSession version check)

**Files:**
- Modify: `lib/eipex/scanner.ex`, `lib/eipex/adapter/session_handler.ex`
- Test: `test/eipex/scanner_test.exs`, `test/eipex/adapter/session_handler_test.exs` (append)

**Interfaces (closing two Phase 3 deferred findings):**
- Scanner: the `rescue` in `handle_call({:request, ...})` narrows to wrap ONLY `build_request/2` (a `try do ... rescue ... end` around the build; send/queue bugs must crash loudly again).
- Adapter: RegisterSession with protocol version ≠ 1 answers encap status 0x0069 with data `<<1::16-little, 0::16-little>>` (the supported version) and does NOT register the session.

- [ ] **Step 1: Write the failing tests**

Append to the scanner test (in the "deferred hardening" describe):

```elixir
    test "rescue is scoped to request building only" do
      # a post-build crash must NOT be converted into {:error, {:invalid_request, _}}:
      # kill the socket out from under the scanner and check the loss contract
      target = ScriptedTarget.start(get_attr_handler(<<1>>))
      pid = start_scanner(target)
      %{socket: socket} = :sys.get_state(pid)
      :gen_tcp.close(socket)

      result = Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1)
      assert result == {:error, :connection_lost}
    end
```

Append to the adapter session test:

```elixir
  test "register session with an unsupported protocol version answers 0x0069" do
    {_pid, port} = start_adapter()
    socket = connect(port)

    bad = %Encap{command: :register_session, data: <<2::16-little, 0::16-little>>}
    send_frame(socket, bad)

    reply = recv_frame(socket)
    assert reply.status == 0x0069
    assert reply.data == <<1::16-little, 0::16-little>>

    # session was not registered: send_rr_data still answers 0x0064
    send_frame(socket, Encap.send_rr_data(1, <<>>))
    assert %Encap{status: 0x0064} = recv_frame(socket)
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_test.exs test/eipex/adapter/session_handler_test.exs`
Expected: the version test FAILS (currently any version registers). The scanner
test may already pass (send failures return tuples, not raises) — it PINS the
contract; note its pre-fix result.

- [ ] **Step 3: Implement**

Scanner — restructure `handle_call({:request, opts}, from, state)`:

```elixir
  def handle_call({:request, opts}, from, state) do
    built =
      try do
        if Keyword.get(opts, :connected, false) do
          :connected
        else
          build_request(opts, state)
        end
      rescue
        exception -> {:invalid, Exception.message(exception)}
      end

    case built do
      :connected -> connected_request(opts, from, state)
      {:invalid, message} -> {:reply, {:error, {:invalid_request, message}}, state}
      {:ok, mr} -> dispatch_request(state, from, mr, Keyword.get(opts, :timeout, state.timeout), :request)
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end
```

(`connected_request/3`'s own `MessageRouter.encode_request` can also raise on a
bad symbolic — wrap ITS build the same way inside `connected_request`, keeping
the send outside; keep it simple and symmetric.)

Adapter session handler — in the `:register_session` clause, before assigning
a handle:

```elixir
  defp handle_frame(state, %Encap{command: :register_session} = frame) do
    cond do
      not is_nil(state.session_handle) ->
        reply(state, %Encap{frame | status: 0x0001})
        state

      not match?(<<1::16-little, _flags::16-little>>, frame.data) ->
        reply(state, %Encap{frame | status: 0x0069, data: <<1::16-little, 0::16-little>>})
        state

      true ->
        handle = :erlang.unique_integer([:positive]) |> rem(0xFFFF_FFFE) |> Kernel.+(1)
        reply(state, %Encap{frame | session_handle: handle})
        %{state | session_handle: handle}
    end
  end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test` (full suite)
Expected: all green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Fixed] Scoped scanner request rescue; RegisterSession rejects unsupported versions`

```bash
mix format && git add -A && git commit -m "fix: phase 3 deferred mini-hardening"
```

---

## Completion criteria for Phase 4

- `mix test` green and hermetic; Phases 1-3 untouched and green.
- Connected loopback suite green (open/request/close/reopen, duplicate triad, session-death cleanup, capacity, class-1 refusal).
- `mix test --include interop` green with the pycomm3 connected read (run for real, output in the task report).
- `mix format --check-formatted`; zero runtime deps; one CHANGELOG line per task.

## After this plan

Phase 5 (class 1 implicit I/O over UDP 2222) replaces the class-0/1 refusal with
`EstablishIoConnection`: per-connection `gen_statem` with RPI production and
watchdog timers, the shared UDP socket with Registry demux, run/idle headers,
and multicast allocation. The ConnectionTable grows o2t/t2o indexing for UDP
demux, and the scanner gets `Eipex.Scanner.IOConnection`.

