# Eipex Phase 2 — Explicit Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working EtherNet/IP scanner for explicit messaging: TCP session process, UCMM `generic_message`, attribute helpers, Unconnected Send routing, NOP keepalive, and UDP ListIdentity discovery — validated against real sockets in every test and against the cpppo PLC simulator for interop.

**Architecture:** Layer 1 (scanner role) of the approved spec, built on the Phase 1 codecs unchanged. One `GenServer` per session owns the TCP socket (`active: :once`), reassembles the stream with `Encap.decode/1`'s `{:ok, frame, rest} | :partial` contract, correlates request/response by sender context, and serializes requests through an internal FIFO queue. Discovery is a plain function over a short-lived UDP socket. No auto-reconnect: on connection loss the process exits `{:shutdown, :connection_lost}` and the application decides (spec §6).

**Tech Stack:** Elixir ≥ 1.15 / OTP ≥ 26, `gen_tcp`/`gen_udp`, ExUnit. Test support: a `ScriptedTarget` module (real TCP listener driven by the real codecs — no mocks). Interop: cpppo via docker compose, tagged `:interop` and excluded by default.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. Test-only deps allowed.
- All multi-byte fields little-endian except sockaddr fields (big-endian) — handled by Phase 1 codecs.
- `decode`-side functions never raise on network input; `encode`/builders may raise on programmer error.
- No mocks: tests exercise real sockets on loopback; the scripted peer uses the real codecs.
- No auto-reconnect in the scanner. Connection loss ⇒ exit `{:shutdown, :connection_lost}`, pending callers get `{:error, :connection_lost}`.
- Run `mix format` before every commit.
- Every commit appends one line to `CHANGELOG.md`: `[Type] What changed`, max 100 chars.
- TDD: write the failing test first, watch it fail, implement, watch it pass, commit.
- Phase 1 suite (83 tests + 3 properties) must stay green throughout.

## File Structure

```
eipex/
├── mix.exs                                # Task 1: elixirc_paths for test/support
├── lib/eipex/
│   ├── scanner.ex                         # Tasks 1-4: session GenServer + public API
│   └── scanner/discovery.ex               # Task 5: UDP ListIdentity discovery
├── test/support/scripted_target.ex        # Task 1: real-TCP scripted peer (test-only)
├── test/eipex/scanner_test.exs            # Tasks 1-4
├── test/eipex/scanner/discovery_test.exs  # Task 5
├── test/interop/cpppo_test.exs            # Task 6: tagged :interop, excluded by default
├── interop/docker-compose.yml             # Task 6: cpppo simulator
└── .github/workflows/ci.yml               # Task 7: CI on custom X64 runner
```

**Public API after this phase** (consumed by Phases 4-6):

```elixir
{:ok, pid}  = Eipex.Scanner.start_link(host: "10.0.0.5")
              # opts: port (44818), route_path (:none | [backplane: slot] | segments),
              #       timeout (5_000), keepalive (60_000 | :none), name
{:ok, resp} = Eipex.Scanner.generic_message(pid, service: 0x0E, class: 0x01,
              instance: 1, attribute: 7)
              # path opts: class/instance/attribute | path: segments-or-binary | symbolic: "Tag"
              # other opts: data (<<>>), timeout, route_path (overrides session default)
              # resp :: %{service, status, status_name, extended, data}
{:ok, bin}  = Eipex.Scanner.get_attribute(pid, 0x01, 1, 7)
:ok         = Eipex.Scanner.set_attribute(pid, 0xF5, 1, 8, <<1>>)
{:ok, ids}  = Eipex.Scanner.discover(address: {255, 255, 255, 255}, timeout: 1_000)
:ok         = Eipex.Scanner.close(pid)
```

CIP-level errors (non-zero general status) are returned inside the `{:ok, resp}` map
from `generic_message` — the caller inspects `status_name`. The `get_attribute`/
`set_attribute` helpers convert them to `{:error, {:cip, status_name, extended}}`.
Transport/encapsulation failures are always `{:error, reason}`.

---

### Task 1: ScriptedTarget test support + session lifecycle

**Files:**
- Modify: `mix.exs` (add `elixirc_paths`)
- Create: `test/support/scripted_target.ex`
- Create: `lib/eipex/scanner.ex` (lifecycle only; request engine comes in Task 2)
- Test: `test/eipex/scanner_test.exs`

**Interfaces:**
- Consumes: `Eipex.Encap` (Task 1-2 of Phase 1): `encode/1`, `decode/1`, `register_session/0`, `unregister_session/1`, struct fields.
- Produces:
  - `Eipex.TestSupport.ScriptedTarget.start(handler, opts \\ []) :: %{port: port, pid: pid}` — listens on an ephemeral loopback port; accepts ONE connection; answers RegisterSession automatically with session handle `0x1234`; for every SendRRData frame calls `handler.(mr_request_binary)` which returns `mr_response_binary` (wrapped and sent back with the **same sender context**) or `:no_reply`. Options: `split_replies: true` (send each reply in two TCP chunks, 10 ms apart). Records every decoded inbound frame; `ScriptedTarget.frames(target)` returns them; `ScriptedTarget.close(target)` closes the socket from the target side.
  - `Eipex.Scanner.start_link(opts) :: {:ok, pid} | {:error, reason}` — connects, registers session in `init/1` (synchronous; failure surfaces at `start_link`).
  - `Eipex.Scanner.close(pid) :: :ok` — sends UnRegisterSession, closes socket, stops `:normal`.
  - Internal `%Eipex.Scanner.State{socket, session_handle, buffer, pending, queue, context_counter, route_path, keepalive, timeout}`.

- [ ] **Step 1: Add test/support to compile paths**

In `mix.exs`, inside `project/0` add:

```elixir
      elixirc_paths: elixirc_paths(Mix.env()),
```

and at the bottom of the module:

```elixir
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
```

- [ ] **Step 2: Write the ScriptedTarget support module**

`test/support/scripted_target.ex`:

```elixir
defmodule Eipex.TestSupport.ScriptedTarget do
  @moduledoc """
  A minimal EtherNet/IP target for tests: a real TCP listener on loopback,
  driven by the real Eipex codecs. Answers RegisterSession automatically;
  every SendRRData is passed (as the raw Message Router request binary) to
  the handler fun, whose binary return is wrapped and sent back with the
  same sender context. No mocks: the scanner under test talks real bytes.
  """

  alias Eipex.{CPF, Encap}

  @session_handle 0x1234

  def start(handler, opts \\ []) do
    parent = self()
    {:ok, listen} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    {:ok, agent} = Agent.start_link(fn -> %{frames: [], socket: nil} end)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen)
        Agent.update(agent, &%{&1 | socket: socket})
        send(parent, {:scripted_target_connected, self()})
        serve(socket, <<>>, handler, agent, opts)
      end)

    %{port: port, pid: pid, agent: agent, listen: listen}
  end

  @doc "All frames received so far, oldest first."
  def frames(%{agent: agent}) do
    agent |> Agent.get(& &1.frames) |> Enum.reverse()
  end

  @doc "Close the connection from the target side."
  def close(%{agent: agent}) do
    case Agent.get(agent, & &1.socket) do
      nil -> :ok
      socket -> :gen_tcp.close(socket)
    end
  end

  defp serve(socket, buffer, handler, agent, opts) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} ->
        buffer = drain(socket, buffer <> data, handler, agent, opts)
        serve(socket, buffer, handler, agent, opts)

      {:error, _} ->
        :ok
    end
  end

  defp drain(socket, buffer, handler, agent, opts) do
    case Encap.decode(buffer) do
      {:ok, frame, rest} ->
        Agent.update(agent, fn s -> %{s | frames: [frame | s.frames]} end)
        handle_frame(socket, frame, handler, opts)
        drain(socket, rest, handler, agent, opts)

      :partial ->
        buffer
    end
  end

  defp handle_frame(socket, %Encap{command: :register_session} = frame, _handler, _opts) do
    reply = %Encap{frame | session_handle: @session_handle}
    :gen_tcp.send(socket, Encap.encode(reply))
  end

  defp handle_frame(socket, %Encap{command: :send_rr_data} = frame, handler, opts) do
    {:ok, cpf} = Encap.unwrap_cpf(frame)
    {:ok, items} = CPF.decode(cpf)
    [{:unconnected_data, mr_request}] = for {:unconnected_data, _} = i <- items, do: i

    case handler.(mr_request) do
      :no_reply ->
        :ok

      mr_response when is_binary(mr_response) ->
        reply_cpf = CPF.encode([:null_address, {:unconnected_data, mr_response}])

        reply = %Encap{
          Encap.send_rr_data(@session_handle, reply_cpf)
          | sender_context: frame.sender_context
        }

        send_reply(socket, Encap.encode(reply), opts)
    end
  end

  defp handle_frame(_socket, %Encap{command: :unregister_session}, _handler, _opts), do: :ok
  defp handle_frame(_socket, %Encap{command: :nop}, _handler, _opts), do: :ok

  defp send_reply(socket, binary, opts) do
    if opts[:split_replies] do
      half = div(byte_size(binary), 2)
      <<a::binary-size(half), b::binary>> = binary
      :gen_tcp.send(socket, a)
      Process.sleep(10)
      :gen_tcp.send(socket, b)
    else
      :gen_tcp.send(socket, binary)
    end
  end
end
```

- [ ] **Step 3: Write the failing lifecycle tests**

`test/eipex/scanner_test.exs`:

```elixir
defmodule Eipex.ScannerTest do
  use ExUnit.Case

  alias Eipex.Encap
  alias Eipex.Scanner
  alias Eipex.TestSupport.ScriptedTarget

  defp noop_handler, do: fn _mr -> :no_reply end

  test "start_link registers a session and close unregisters it" do
    target = ScriptedTarget.start(noop_handler())

    {:ok, pid} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)
    assert_receive {:scripted_target_connected, _}, 1_000

    assert :ok = Scanner.close(pid)
    refute Process.alive?(pid)

    # give the target loop a beat to decode the trailing frames
    Process.sleep(50)

    commands = target |> ScriptedTarget.frames() |> Enum.map(& &1.command)
    assert commands == [:register_session, :unregister_session]
  end

  test "start_link returns an error when nothing listens" do
    Process.flag(:trap_exit, true)
    assert {:error, :econnrefused} = Scanner.start_link(host: {127, 0, 0, 1}, port: 1)
  end

  test "session handle from the target is stored and used" do
    target = ScriptedTarget.start(noop_handler())
    {:ok, pid} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    assert %{session_handle: 0x1234} = :sys.get_state(pid)
    Scanner.close(pid)
  end
end
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_test.exs`
Expected: FAIL — `Eipex.Scanner.start_link/1 is undefined`.

- [ ] **Step 5: Implement the Scanner lifecycle**

`lib/eipex/scanner.ex`:

```elixir
defmodule Eipex.Scanner do
  @moduledoc """
  EtherNet/IP scanner (originator) session for explicit messaging.

  One process per target device: owns the TCP connection to port 44818,
  registers the encapsulation session, and serializes UCMM requests.
  There is no automatic reconnection: when the connection drops, the
  process exits `{:shutdown, :connection_lost}` and the owning
  application decides whether and when to retry.
  """

  use GenServer

  alias Eipex.Encap

  @default_port 44_818
  @default_timeout 5_000
  @default_keepalive 60_000

  defmodule State do
    @moduledoc false
    defstruct socket: nil,
              session_handle: nil,
              buffer: <<>>,
              pending: nil,
              queue: :queue.new(),
              context_counter: 0,
              route_path: :none,
              keepalive: nil,
              timeout: nil
  end

  # -- Public API --------------------------------------------------------------

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @spec close(GenServer.server()) :: :ok
  def close(server), do: GenServer.call(server, :close)

  # -- GenServer ---------------------------------------------------------------

  @impl true
  def init(opts) do
    host = opts |> Keyword.fetch!(:host) |> normalize_host()
    port = Keyword.get(opts, :port, @default_port)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    socket_opts = [:binary, packet: :raw, active: false, keepalive: true]

    with {:ok, socket} <- :gen_tcp.connect(host, port, socket_opts, timeout),
         {:ok, handle} <- register_session(socket, timeout) do
      :ok = :inet.setopts(socket, active: :once)

      {:ok,
       %State{
         socket: socket,
         session_handle: handle,
         route_path: opts |> Keyword.get(:route_path, :none) |> normalize_route(),
         keepalive: Keyword.get(opts, :keepalive, @default_keepalive),
         timeout: timeout
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:close, _from, state) do
    _ = :gen_tcp.send(state.socket, Encap.encode(Encap.unregister_session(state.session_handle)))
    :gen_tcp.close(state.socket)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:tcp, socket, _data}, %State{socket: socket} = state) do
    # Request/response handling arrives in Task 2; reactivate for now.
    :ok = :inet.setopts(socket, active: :once)
    {:noreply, state}
  end

  def handle_info({:tcp_closed, socket}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, state}
  end

  def handle_info({:tcp_error, socket, _reason}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, state}
  end

  # -- Session registration (passive mode, inside init) -------------------------

  defp register_session(socket, timeout) do
    with :ok <- :gen_tcp.send(socket, Encap.encode(Encap.register_session())),
         {:ok, %Encap{command: :register_session, status: 0, session_handle: handle}} <-
           recv_frame(socket, <<>>, timeout) do
      {:ok, handle}
    else
      {:ok, %Encap{status: status}} -> {:error, {:encap, Encap.status_name(status)}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp recv_frame(socket, buffer, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        case Encap.decode(buffer <> data) do
          {:ok, frame, _rest} -> {:ok, frame}
          :partial -> recv_frame(socket, buffer <> data, timeout)
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # -- Option normalization ------------------------------------------------------

  defp normalize_host(host) when is_binary(host), do: String.to_charlist(host)
  defp normalize_host(host), do: host

  defp normalize_route(:none), do: :none
  defp normalize_route(backplane: slot), do: [{:port, 1, slot}]
  defp normalize_route(segments) when is_list(segments), do: segments
end
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_test.exs`
Expected: PASS, 3 tests, 0 failures. Then `mix test` — Phase 1 suite still green (86 tests + 3 properties total).

- [ ] **Step 7: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner session lifecycle (RegisterSession over TCP) and scripted test target`

```bash
mix format && git add -A && git commit -m "feat: scanner session lifecycle"
```

---

### Task 2: Request engine + `generic_message/2`

**Files:**
- Modify: `lib/eipex/scanner.ex`
- Test: `test/eipex/scanner_test.exs` (append)

**Interfaces:**
- Consumes: `Eipex.CPF.encode/1`, `Eipex.CIP.MessageRouter.encode_request/3` + `decode_response/1`, `Encap.send_rr_data/2`, `Encap.unwrap_cpf/1`; ScriptedTarget from Task 1.
- Produces:
  - `Eipex.Scanner.generic_message(server, opts) :: {:ok, response_map} | {:error, reason}` where `response_map` is exactly `MessageRouter.decode_response/1`'s map. Opts: `service` (required), path via `class:`/`instance:`/`attribute:` or `path:` (segments or binary) or `symbolic:`; `data:` (default `<<>>`); `timeout:` (default session timeout).
  - CIP errors (non-zero general status) come back inside `{:ok, resp}`; `{:error, reason}` is reserved for transport/encap/malformed failures and `:timeout`.
  - Requests are serialized: one outstanding on the wire, the rest FIFO-queued in the GenServer; correlation by sender context (64-bit counter); stale/unsolicited responses are ignored.
  - Known limitation (documented, not solved here): a caller's `GenServer.call` clock starts on enqueue while its per-request timer starts on send, so a deeply queued request behind a slow target can exit the caller before its own `:timeout` reply. Acceptable for explicit messaging (requests are short); revisit only if it bites.

- [ ] **Step 1: Write the failing tests (append inside `Eipex.ScannerTest`)**

```elixir
  alias Eipex.CIP.MessageRouter

  defp get_attr_handler(reply_data) do
    fn mr ->
      {:ok, %{service: 0x0E, path: _path, data: <<>>}} = MessageRouter.decode_request(mr)
      MessageRouter.encode_response(0x0E, 0x00, data: reply_data)
    end
  end

  defp start_scanner(target, opts \\ []) do
    {:ok, pid} =
      Scanner.start_link([host: {127, 0, 0, 1}, port: target.port] ++ opts)

    pid
  end

  describe "generic_message/2" do
    test "round-trips a UCMM request" do
      target = ScriptedTarget.start(get_attr_handler(<<0x4D, 0x00>>))
      pid = start_scanner(target)

      assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 0x01, instance: 1, attribute: 1)

      Scanner.close(pid)
    end

    test "reassembles responses split across TCP segments" do
      target = ScriptedTarget.start(get_attr_handler(<<1, 2, 3, 4>>), split_replies: true)
      pid = start_scanner(target)

      assert {:ok, %{status_name: :success, data: <<1, 2, 3, 4>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 0x01, instance: 1, attribute: 1)

      Scanner.close(pid)
    end

    test "returns CIP errors inside the ok tuple" do
      handler = fn _mr -> MessageRouter.encode_response(0x0E, 0x05) end
      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:ok, %{status: 0x05, status_name: :path_destination_unknown}} =
               Scanner.generic_message(pid, service: 0x0E, class: 0x77, instance: 9, attribute: 1)

      Scanner.close(pid)
    end

    test "times out when the target does not answer, and recovers" do
      calls = :counters.new(1, [])

      handler = fn mr ->
        :counters.add(calls, 1, 1)

        if :counters.get(calls, 1) == 1 do
          :no_reply
        else
          {:ok, %{service: service}} = MessageRouter.decode_request(mr)
          MessageRouter.encode_response(service, 0x00, data: <<0xAA>>)
        end
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:error, :timeout} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 100)

      assert {:ok, %{data: <<0xAA>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1)

      Scanner.close(pid)
    end

    test "serializes concurrent requests through the queue" do
      handler = fn mr ->
        {:ok, %{service: 0x0E, path: path}} = MessageRouter.decode_request(mr)
        {:ok, segments} = Eipex.CIP.Path.decode(path)
        instance = Keyword.fetch!(segments, :instance)
        MessageRouter.encode_response(0x0E, 0x00, data: <<instance>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      tasks =
        for i <- 1..5 do
          Task.async(fn ->
            Scanner.generic_message(pid, service: 0x0E, class: 1, instance: i)
          end)
        end

      results = Task.await_many(tasks, 5_000)

      for {result, i} <- Enum.zip(results, 1..5) do
        assert {:ok, %{data: <<^i>>}} = result
      end

      Scanner.close(pid)
    end

    test "symbolic option builds an ANSI symbolic path" do
      handler = fn mr ->
        {:ok, %{service: 0x4C, path: <<0x91, 0x05, "SCADA", 0x00>>}} =
          MessageRouter.decode_request(mr)

        MessageRouter.encode_response(0x4C, 0x00, data: <<0xC3, 0x00, 7, 0>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:ok, %{status_name: :success}} =
               Scanner.generic_message(pid, service: 0x4C, symbolic: "SCADA", data: <<1::16-little>>)

      Scanner.close(pid)
    end

    test "missing service or path returns an error without touching the wire" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target)

      assert {:error, :missing_service} = Scanner.generic_message(pid, class: 1)
      assert {:error, :missing_path} = Scanner.generic_message(pid, service: 0x0E)

      Scanner.close(pid)
    end
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_test.exs`
Expected: FAIL — `Scanner.generic_message/2 is undefined`. Task 1 tests still pass.

- [ ] **Step 3: Implement the request engine**

Add to `lib/eipex/scanner.ex` — new aliases at the top:

```elixir
  alias Eipex.{CPF, Encap}
  alias Eipex.CIP.MessageRouter
```

(replace the existing bare `alias Eipex.Encap`). Public API:

```elixir
  @type response :: %{
          service: byte(),
          status: byte(),
          status_name: atom(),
          extended: [non_neg_integer()],
          data: binary()
        }

  @spec generic_message(GenServer.server(), keyword()) ::
          {:ok, response()} | {:error, term()}
  def generic_message(server, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    GenServer.call(server, {:request, opts}, timeout + 1_000)
  end
```

New `handle_call` clause (before `:close`):

```elixir
  @impl true
  def handle_call({:request, opts}, from, state) do
    case build_request(opts, state) do
      {:ok, mr} ->
        timeout = Keyword.get(opts, :timeout, state.timeout)

        if state.pending do
          {:noreply, %{state | queue: :queue.in({from, mr, timeout}, state.queue)}}
        else
          {:noreply, send_request(state, from, mr, timeout)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end
```

Replace the placeholder `{:tcp, ...}` clause and add the timeout clause:

```elixir
  @impl true
  def handle_info({:tcp, socket, data}, %State{socket: socket} = state) do
    state = drain_frames(%{state | buffer: state.buffer <> data})
    :ok = :inet.setopts(socket, active: :once)
    {:noreply, state}
  end

  def handle_info({:request_timeout, context}, state) do
    case state.pending do
      {from, ^context, _timer} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, next_request(%{state | pending: nil})}

      _ ->
        {:noreply, state}
    end
  end
```

Private machinery:

```elixir
  # -- Request pipeline ----------------------------------------------------------

  defp build_request(opts, _state) do
    with {:ok, service} <- Keyword.fetch(opts, :service),
         {:ok, path} <- request_path(opts) do
      {:ok, MessageRouter.encode_request(service, path, Keyword.get(opts, :data, <<>>))}
    else
      :error -> {:error, :missing_service}
      {:error, _} = error -> error
    end
  end

  defp request_path(opts) do
    cond do
      path = opts[:path] ->
        {:ok, path}

      name = opts[:symbolic] ->
        {:ok, [{:symbolic, name}]}

      class = opts[:class] ->
        base = [{:class, class}, {:instance, Keyword.get(opts, :instance, 1)}]

        case opts[:attribute] do
          nil -> {:ok, base}
          attribute -> {:ok, base ++ [{:attribute, attribute}]}
        end

      true ->
        {:error, :missing_path}
    end
  end

  defp send_request(state, from, mr, timeout) do
    context = <<state.context_counter::64-little>>
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}])

    frame = %Encap{
      Encap.send_rr_data(state.session_handle, cpf)
      | sender_context: context
    }

    :ok = :gen_tcp.send(state.socket, Encap.encode(frame))
    timer = Process.send_after(self(), {:request_timeout, context}, timeout)

    %{state | pending: {from, context, timer}, context_counter: state.context_counter + 1}
  end

  defp next_request(%State{pending: nil} = state) do
    case :queue.out(state.queue) do
      {{:value, {from, mr, timeout}}, queue} ->
        send_request(%{state | queue: queue}, from, mr, timeout)

      {:empty, _} ->
        state
    end
  end

  # -- Inbound frames --------------------------------------------------------------

  defp drain_frames(state) do
    case Encap.decode(state.buffer) do
      {:ok, frame, rest} ->
        %{state | buffer: rest} |> handle_frame(frame) |> drain_frames()

      :partial ->
        state
    end
  end

  defp handle_frame(
         %State{pending: {from, context, timer}} = state,
         %Encap{command: :send_rr_data, sender_context: context} = frame
       ) do
    Process.cancel_timer(timer)
    GenServer.reply(from, decode_reply(frame))
    next_request(%{state | pending: nil})
  end

  defp handle_frame(state, %Encap{}), do: state

  defp decode_reply(%Encap{status: 0} = frame) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [mr | _] <- for({:unconnected_data, d} <- items, do: d),
         {:ok, response} <- MessageRouter.decode_response(mr) do
      {:ok, response}
    else
      [] -> {:error, :no_data_item}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_reply(%Encap{status: status}) do
    {:error, {:encap, Encap.status_name(status)}}
  end
```

Note on correlation: `handle_frame/2`'s first clause binds `context` twice (in the
state's pending tuple and the frame's sender context) — the repeated variable is an
equality match, so only the response to the outstanding request is accepted; a late
response after a timeout has a stale context and falls through to the ignore clause.

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_test.exs`
Expected: PASS, 10 tests, 0 failures. Then full `mix test` — everything green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner generic_message: UCMM requests with correlation, queueing and timeouts`

```bash
mix format && git add -A && git commit -m "feat: scanner UCMM request engine"
```

---

### Task 3: Unconnected Send routing + attribute helpers

**Files:**
- Modify: `lib/eipex/scanner.ex`
- Test: `test/eipex/scanner_test.exs` (append)

**Interfaces:**
- Consumes: `Eipex.CIP.ConnectionManager.encode_unconnected_send/3` (Phase 1 Task 7); `build_request/2` and `unwrap_cip` helpers from Task 2.
- Produces:
  - `route_path` session option and per-request override: `:none` (default) | `[backplane: slot]` sugar | raw segment list (e.g. `[{:port, 1, 0}]`). When not `:none`, the MR request is wrapped in Unconnected Send (0x52) to the Connection Manager.
  - `Eipex.Scanner.get_attribute(server, class, instance, attribute, opts \\ []) :: {:ok, binary} | {:error, {:cip, atom, [integer]}} | {:error, term}` — Get_Attribute_Single (0x0E)
  - `Eipex.Scanner.get_attributes_all(server, class, instance, opts \\ []) :: same` — 0x01
  - `Eipex.Scanner.set_attribute(server, class, instance, attribute, data, opts \\ []) :: :ok | {:error, ...}` — 0x10

- [ ] **Step 1: Write the failing tests (append inside `Eipex.ScannerTest`)**

```elixir
  # Splits an Unconnected Send request payload into {embedded_mr, route_path_bytes}.
  defp unwrap_unconnected_send(data) do
    <<_ptt, _ticks, size::16-little, embedded::binary-size(size), rest::binary>> = data
    rest = if rem(size, 2) == 1, do: binary_part(rest, 1, byte_size(rest) - 1), else: rest
    <<route_words, 0x00, route::binary-size(route_words * 2)>> = rest
    {embedded, route}
  end

  describe "route_path" do
    test "wraps requests in Unconnected Send and replies with the embedded response" do
      handler = fn mr ->
        {:ok, %{service: 0x52, path: <<0x20, 0x06, 0x24, 0x01>>, data: data}} =
          MessageRouter.decode_request(mr)

        {embedded, route} = unwrap_unconnected_send(data)
        assert route == <<0x01, 0x00>>

        {:ok, %{service: 0x0E}} = MessageRouter.decode_request(embedded)
        MessageRouter.encode_response(0x0E, 0x00, data: <<0x63>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target, route_path: [backplane: 0])

      assert {:ok, %{status_name: :success, data: <<0x63>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, attribute: 7)

      Scanner.close(pid)
    end

    test "per-request route_path overrides the session default" do
      handler = fn mr ->
        {:ok, %{service: service}} = MessageRouter.decode_request(mr)
        # session default is :none, so this arrives unwrapped
        assert service == 0x0E
        MessageRouter.encode_response(0x0E, 0x00, data: <<1>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target, route_path: :none)

      assert {:ok, _} =
               Scanner.generic_message(pid,
                 service: 0x0E, class: 1, instance: 1, route_path: :none)

      Scanner.close(pid)
    end
  end

  describe "attribute helpers" do
    test "get_attribute returns the raw attribute data" do
      target = ScriptedTarget.start(get_attr_handler(<<0x4D, 0x00>>))
      pid = start_scanner(target)

      assert {:ok, <<0x4D, 0x00>>} = Scanner.get_attribute(pid, 0x01, 1, 1)
      Scanner.close(pid)
    end

    test "get_attribute surfaces CIP errors as error tuples" do
      handler = fn _mr -> MessageRouter.encode_response(0x0E, 0x14, extended: [0x0001]) end
      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:error, {:cip, :attribute_not_supported, [0x0001]}} =
               Scanner.get_attribute(pid, 0x01, 1, 99)

      Scanner.close(pid)
    end

    test "set_attribute returns :ok on success" do
      handler = fn mr ->
        {:ok, %{service: 0x10, data: <<0x01>>}} = MessageRouter.decode_request(mr)
        MessageRouter.encode_response(0x10, 0x00)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert :ok = Scanner.set_attribute(pid, 0xF5, 1, 8, <<0x01>>)
      Scanner.close(pid)
    end

    test "get_attributes_all uses service 0x01 without an attribute segment" do
      handler = fn mr ->
        {:ok, %{service: 0x01, path: <<0x20, 0x01, 0x24, 0x01>>}} =
          MessageRouter.decode_request(mr)

        MessageRouter.encode_response(0x01, 0x00, data: <<9, 9>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:ok, <<9, 9>>} = Scanner.get_attributes_all(pid, 0x01, 1)
      Scanner.close(pid)
    end
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_test.exs`
Expected: FAIL — first route test fails (request arrives unwrapped: handler crashes on service mismatch → scanner times out) and `get_attribute/4` is undefined.

- [ ] **Step 3: Implement routing and helpers**

Add alias: `alias Eipex.CIP.ConnectionManager`. Public helpers:

```elixir
  @spec get_attribute(GenServer.server(), non_neg_integer(), non_neg_integer(),
          non_neg_integer(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def get_attribute(server, class, instance, attribute, opts \\ []) do
    opts = Keyword.merge(opts, service: 0x0E, class: class, instance: instance, attribute: attribute)
    server |> generic_message(opts) |> unwrap_cip()
  end

  @spec get_attributes_all(GenServer.server(), non_neg_integer(), non_neg_integer(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def get_attributes_all(server, class, instance, opts \\ []) do
    opts = Keyword.merge(opts, service: 0x01, class: class, instance: instance)
    server |> generic_message(opts) |> unwrap_cip()
  end

  @spec set_attribute(GenServer.server(), non_neg_integer(), non_neg_integer(),
          non_neg_integer(), binary(), keyword()) ::
          :ok | {:error, term()}
  def set_attribute(server, class, instance, attribute, data, opts \\ []) do
    opts =
      Keyword.merge(opts,
        service: 0x10, class: class, instance: instance, attribute: attribute, data: data)

    case server |> generic_message(opts) |> unwrap_cip() do
      {:ok, _data} -> :ok
      error -> error
    end
  end

  defp unwrap_cip({:ok, %{status_name: :success, data: data}}), do: {:ok, data}
  defp unwrap_cip({:ok, %{status_name: name, extended: extended}}), do: {:error, {:cip, name, extended}}
  defp unwrap_cip({:error, _} = error), do: error
```

In `build_request/2`, wrap with Unconnected Send when a route applies:

```elixir
  defp build_request(opts, state) do
    with {:ok, service} <- Keyword.fetch(opts, :service),
         {:ok, path} <- request_path(opts) do
      mr = MessageRouter.encode_request(service, path, Keyword.get(opts, :data, <<>>))

      case request_route(opts, state) do
        :none -> {:ok, mr}
        route -> {:ok, ConnectionManager.encode_unconnected_send(mr, route, [])}
      end
    else
      :error -> {:error, :missing_service}
      {:error, _} = error -> error
    end
  end

  defp request_route(opts, state) do
    case Keyword.fetch(opts, :route_path) do
      {:ok, route} -> normalize_route(route)
      :error -> state.route_path
    end
  end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_test.exs`
Expected: PASS, 16 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner Unconnected Send routing and get/set attribute helpers`

```bash
mix format && git add -A && git commit -m "feat: scanner routing and attribute helpers"
```

---

### Task 4: NOP keepalive + connection-loss semantics

**Files:**
- Modify: `lib/eipex/scanner.ex`
- Test: `test/eipex/scanner_test.exs` (append)

**Interfaces:**
- Consumes: `Encap.nop/0`; ScriptedTarget's `frames/1` and `close/1`.
- Produces:
  - `keepalive:` option (default `60_000` ms, `:none` disables): the scanner sends a NOP frame every interval to defeat the adapter's 120 s encapsulation inactivity timeout (spec §6).
  - Connection loss (`tcp_closed`/`tcp_error`): the pending caller and every queued caller receive `{:error, :connection_lost}`; the process exits `{:shutdown, :connection_lost}`. No reconnect.
  - `close/1` while requests are in flight: pending and queued callers receive `{:error, :closed}` before the process stops.

- [ ] **Step 1: Write the failing tests (append inside `Eipex.ScannerTest`)**

```elixir
  describe "keepalive and connection loss" do
    test "sends NOP frames at the configured interval" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target, keepalive: 50)

      Process.sleep(180)
      Scanner.close(pid)
      Process.sleep(50)

      nops = target |> ScriptedTarget.frames() |> Enum.count(&(&1.command == :nop))
      assert nops >= 2
    end

    test "keepalive: :none sends no NOPs" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target, keepalive: :none)

      Process.sleep(150)
      Scanner.close(pid)
      Process.sleep(50)

      assert target |> ScriptedTarget.frames() |> Enum.count(&(&1.command == :nop)) == 0
    end

    test "connection loss fails the in-flight caller and stops the process" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target)
      ref = Process.monitor(pid)

      caller =
        Task.async(fn ->
          Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 5_000)
        end)

      # let the request reach the wire, then drop the connection target-side
      Process.sleep(50)
      ScriptedTarget.close(target)

      assert {:error, :connection_lost} = Task.await(caller, 1_000)
      assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :connection_lost}}, 1_000
    end
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_test.exs`
Expected: FAIL — no NOPs are sent (first test) and the in-flight caller times out with the wrong reason (third test).

- [ ] **Step 3: Implement keepalive and loss handling**

In `init/1`, after building the state, schedule the first keepalive:

```elixir
      {:ok, schedule_keepalive(state)}
```

Add the info clauses and helpers:

```elixir
  def handle_info(:keepalive, state) do
    _ = :gen_tcp.send(state.socket, Encap.encode(Encap.nop()))
    {:noreply, schedule_keepalive(state)}
  end
```

Update the two loss clauses to flush callers first:

```elixir
  def handle_info({:tcp_closed, socket}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, fail_callers(state, {:error, :connection_lost})}
  end

  def handle_info({:tcp_error, socket, _reason}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, fail_callers(state, {:error, :connection_lost})}
  end
```

Update `handle_call(:close, ...)` to flush before stopping:

```elixir
  def handle_call(:close, _from, state) do
    state = fail_callers(state, {:error, :closed})
    _ = :gen_tcp.send(state.socket, Encap.encode(Encap.unregister_session(state.session_handle)))
    :gen_tcp.close(state.socket)
    {:stop, :normal, :ok, state}
  end
```

Helpers:

```elixir
  defp schedule_keepalive(%State{keepalive: :none} = state), do: state

  defp schedule_keepalive(%State{keepalive: interval} = state) when is_integer(interval) do
    Process.send_after(self(), :keepalive, interval)
    state
  end

  defp fail_callers(state, reply) do
    case state.pending do
      {from, _context, timer} ->
        Process.cancel_timer(timer)
        GenServer.reply(from, reply)

      nil ->
        :ok
    end

    for {from, _mr, _timeout} <- :queue.to_list(state.queue) do
      GenServer.reply(from, reply)
    end

    %{state | pending: nil, queue: :queue.new()}
  end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_test.exs`
Expected: PASS, 19 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner NOP keepalive and explicit connection-loss semantics`

```bash
mix format && git add -A && git commit -m "feat: scanner keepalive and connection-loss handling"
```

---

### Task 5: UDP ListIdentity discovery

**Files:**
- Create: `lib/eipex/scanner/discovery.ex`
- Modify: `lib/eipex/scanner.ex` (add `discover/1` defdelegate)
- Test: `test/eipex/scanner/discovery_test.exs`

**Interfaces:**
- Consumes: `Encap.list_identity/0`, `Encap.encode/1`, `Encap.decode/1`, `CPF.decode/1`, `%Eipex.Identity{}`.
- Produces:
  - `Eipex.Scanner.Discovery.discover(opts \\ []) :: {:ok, [Eipex.Identity.t()]} | {:error, term}` — opts: `address` (default `{255, 255, 255, 255}`), `port` (44818), `timeout` (1000 ms collection window). Sends one ListIdentity datagram, collects every reply until the deadline, ignores malformed datagrams.
  - `Eipex.Scanner.discover(opts \\ [])` — defdelegate.

- [ ] **Step 1: Write the failing tests**

`test/eipex/scanner/discovery_test.exs`:

```elixir
defmodule Eipex.Scanner.DiscoveryTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap, Identity}
  alias Eipex.Scanner.Discovery

  @identity %Identity{
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex",
    ip: {127, 0, 0, 1},
    port: 44_818,
    state: 3
  }

  # A one-shot UDP responder speaking the real protocol.
  defp start_responder(reply_fun) do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(socket)

    Task.start_link(fn ->
      {:ok, {ip, sport, data}} = :gen_udp.recv(socket, 0, 5_000)
      {:ok, %Encap{command: :list_identity}, <<>>} = Encap.decode(data)

      case reply_fun.() do
        nil -> :ok
        reply -> :gen_udp.send(socket, ip, sport, reply)
      end

      :gen_udp.close(socket)
    end)

    port
  end

  test "discover collects identity items from replies" do
    reply =
      Encap.encode(%Encap{
        command: :list_identity,
        data: CPF.encode([{:identity, @identity}])
      })

    port = start_responder(fn -> reply end)

    assert {:ok, [%Identity{product_name: "Eipex", vendor_id: 0x4D}]} =
             Discovery.discover(address: {127, 0, 0, 1}, port: port, timeout: 300)
  end

  test "discover ignores malformed datagrams" do
    port = start_responder(fn -> <<0xDE, 0xAD, 0xBE, 0xEF>> end)

    assert {:ok, []} = Discovery.discover(address: {127, 0, 0, 1}, port: port, timeout: 300)
  end

  test "discover returns empty list when nobody answers" do
    port = start_responder(fn -> nil end)

    assert {:ok, []} = Discovery.discover(address: {127, 0, 0, 1}, port: port, timeout: 200)
  end

  test "Eipex.Scanner.discover/1 delegates" do
    port = start_responder(fn -> nil end)

    assert {:ok, []} =
             Eipex.Scanner.discover(address: {127, 0, 0, 1}, port: port, timeout: 200)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner/discovery_test.exs`
Expected: FAIL — `Discovery.discover/1 is undefined`.

- [ ] **Step 3: Implement discovery**

`lib/eipex/scanner/discovery.ex`:

```elixir
defmodule Eipex.Scanner.Discovery do
  @moduledoc """
  EtherNet/IP device discovery: ListIdentity over UDP (broadcast or unicast).
  Every device on the segment answers with its Identity item.
  """

  alias Eipex.{CPF, Encap}
  alias Eipex.Identity

  @default_address {255, 255, 255, 255}
  @default_port 44_818
  @default_timeout 1_000

  @spec discover(keyword()) :: {:ok, [Identity.t()]} | {:error, term()}
  def discover(opts \\ []) do
    address = Keyword.get(opts, :address, @default_address)
    port = Keyword.get(opts, :port, @default_port)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    with {:ok, socket} <- :gen_udp.open(0, [:binary, active: false, broadcast: true]),
         :ok <- :gen_udp.send(socket, address, port, Encap.encode(Encap.list_identity())) do
      deadline = System.monotonic_time(:millisecond) + timeout
      identities = collect(socket, deadline, [])
      :gen_udp.close(socket)
      {:ok, identities}
    end
  end

  defp collect(socket, deadline, acc) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      Enum.reverse(acc)
    else
      case :gen_udp.recv(socket, 0, remaining) do
        {:ok, {_ip, _port, data}} -> collect(socket, deadline, parse(data) ++ acc)
        {:error, _} -> Enum.reverse(acc)
      end
    end
  end

  defp parse(data) do
    with {:ok, %Encap{command: :list_identity, status: 0, data: cpf}, _rest} <- Encap.decode(data),
         {:ok, items} <- CPF.decode(cpf) do
      for {:identity, identity} <- items, do: identity
    else
      _ -> []
    end
  end
end
```

In `lib/eipex/scanner.ex` add:

```elixir
  defdelegate discover(opts \\ []), to: Eipex.Scanner.Discovery
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner/discovery_test.exs`
Expected: PASS, 4 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] UDP ListIdentity discovery (broadcast and unicast)`

```bash
mix format && git add -A && git commit -m "feat: ListIdentity discovery"
```

---

### Task 6: cpppo interop harness

**Files:**
- Create: `interop/docker-compose.yml`
- Create: `test/interop/cpppo_test.exs`
- Modify: `test/test_helper.exs` (exclude `:interop` by default)
- Modify: `README.md` (interop section)

**Interfaces:**
- Consumes: the full Phase 2 scanner API; Docker + Compose (available on this machine — verified).
- Produces: a repeatable interop harness. `mix test` stays hermetic; `mix test --include interop` runs against a live cpppo simulator.

- [ ] **Step 1: Write the compose file**

`interop/docker-compose.yml`:

```yaml
services:
  cpppo:
    image: python:3.11-slim
    command: >
      sh -c "pip install --quiet cpppo &&
             python -m cpppo.server.enip --address 0.0.0.0:44818 -v SCADA=INT[1000]"
    ports:
      - "44818:44818"
```

- [ ] **Step 2: Exclude interop tests by default**

`test/test_helper.exs` becomes:

```elixir
ExUnit.configure(exclude: [:interop])
ExUnit.start()
```

- [ ] **Step 3: Write the interop tests**

`test/interop/cpppo_test.exs`:

```elixir
defmodule Eipex.Interop.CpppoTest do
  @moduledoc """
  Interop against the cpppo Logix simulator (UCMM only).
  Start it first: docker compose -f interop/docker-compose.yml up -d
  Run with: mix test --include interop
  """

  use ExUnit.Case

  alias Eipex.CIP.Types
  alias Eipex.Scanner

  @moduletag :interop
  @host System.get_env("CPPPO_HOST", "127.0.0.1")

  test "registers a session, reads and writes a tag" do
    {:ok, plc} = Scanner.start_link(host: @host)

    # Write SCADA[0] = 42 (Write Tag 0x4D: type INT + element count + value)
    {:ok, write} =
      Scanner.generic_message(plc,
        service: 0x4D,
        symbolic: "SCADA",
        data: <<0xC3, 0x00, 1::16-little, 42::16-little>>
      )

    assert write.status_name == :success

    # Read it back (Read Tag 0x4C: element count)
    {:ok, read} =
      Scanner.generic_message(plc,
        service: 0x4C,
        symbolic: "SCADA",
        data: <<1::16-little>>
      )

    assert read.status_name == :success
    assert {:ok, {:int, 42}} = Types.decode_typed(read.data)

    :ok = Scanner.close(plc)
  end

  test "unknown tag returns a CIP error, not a crash" do
    {:ok, plc} = Scanner.start_link(host: @host)

    {:ok, resp} =
      Scanner.generic_message(plc,
        service: 0x4C,
        symbolic: "NO_SUCH_TAG",
        data: <<1::16-little>>
      )

    refute resp.status_name == :success
    :ok = Scanner.close(plc)
  end
end
```

- [ ] **Step 4: Run the interop suite for real**

```bash
docker compose -f interop/docker-compose.yml up -d
# wait for the simulator to come up (pip install inside the container takes ~20-60 s)
sleep 45
mix test --include interop test/interop/cpppo_test.exs
docker compose -f interop/docker-compose.yml down
```

Expected: 2 tests, 0 failures. If cpppo answers the read with a different but
well-formed shape (e.g. an INT list), adjust the assertion to match observed reality
and record exactly what cpppo returned in your report — the point of this task is
discovering real-device behavior. Also confirm `mix test` (without the include flag)
still runs 0 interop tests.

- [ ] **Step 5: Document it**

Append to `README.md`:

```markdown
## Interop testing

`mix test` is hermetic. To run interop tests against the cpppo Logix simulator:

    docker compose -f interop/docker-compose.yml up -d
    mix test --include interop
    docker compose -f interop/docker-compose.yml down
```

- [ ] **Step 6: Format and commit**

Append to `CHANGELOG.md`: `- [Added] cpppo interop harness (docker compose + tagged interop tests)`

```bash
mix format && git add -A && git commit -m "test: cpppo interop harness"
```

---

### Task 7: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing new. Organization constraint: custom runners `X64`/`ARM64`, never `ubuntu-latest`.
- Produces: CI running format check + hermetic test suite on every push/PR.

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: X64
    steps:
      - uses: actions/checkout@v4
      - uses: erlef/setup-beam@v1
        with:
          otp-version: "27"
          elixir-version: "1.18"
      - uses: actions/cache@v4
        with:
          path: |
            deps
            _build
          key: mix-${{ runner.os }}-${{ hashFiles('mix.lock') }}
      - run: mix deps.get
      - run: mix format --check-formatted
      - run: mix test
```

- [ ] **Step 2: Validate locally what can be validated**

Run: `mix format --check-formatted && mix test`
Expected: both green (CI mirrors exactly these commands). YAML sanity check:
`ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml")' 2>/dev/null || python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: no output (valid YAML). (If neither ruby nor python has yaml, skip — the file is short enough to eyeball.)

- [ ] **Step 3: Format and commit**

Append to `CHANGELOG.md`: `- [Added] CI workflow (format check + tests) on X64 runner`

```bash
mix format && git add -A && git commit -m "ci: format and test workflow"
```

---

## Completion criteria for Phase 2

- `mix test` green and hermetic (no network beyond loopback; interop excluded).
- `mix test --include interop` green against cpppo via docker compose (run at least once, output in the task report).
- `mix format --check-formatted` passes.
- Zero runtime dependencies.
- Phase 1 suite untouched and green.
- `CHANGELOG.md` has one `[Added]` line per task.

## After this plan

Phase 3 (explicit adapter: listener, sessions, MessageRouter dispatch, standard
objects) gets its own plan. The `ScriptedTarget` test module is intentionally
minimal — it is NOT the seed of the Phase 3 adapter; the adapter starts from the
spec's object model, and once it exists, the loopback tests (our scanner ↔ our
adapter) supersede most scripted-target scenarios.

