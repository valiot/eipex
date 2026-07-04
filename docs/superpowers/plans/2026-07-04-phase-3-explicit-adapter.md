# Eipex Phase 3 — Explicit Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working EtherNet/IP adapter (target) for explicit messaging: TCP listener + per-connection session handlers, Message Router dispatch to CIP object modules (Identity, Assembly, Connection Manager with Unconnected Send, TCP/IP Interface, Ethernet Link), an application `Handler` behaviour, UDP ListIdentity discovery responder — validated by loopback tests against our own scanner and by a real pycomm3 interop run.

**Architecture:** Layer 2 (adapter role) of the approved spec. modbux-style process tree: `Eipex.Adapter` (GenServer that owns and links an `AssemblyStore`, a `DynamicSupervisor` for session handlers, a `Listener`, and optionally a `Discovery` responder). Each TCP connection gets a `SessionHandler` GenServer (encapsulation framing, session handle assignment, 120 s inactivity timeout). `Eipex.Adapter.MessageRouter.dispatch/3` is a pure function from an MR request binary to an MR response binary, routing by class code to modules implementing the `Eipex.Adapter.Object` behaviour. Assemblies live in an `AssemblyStore` GenServer keyed by instance.

**Tech Stack:** Elixir/OTP only (gen_tcp/gen_udp), Phase 1 codecs unchanged except two small additions (Task 1), Phase 2 scanner used as the loopback test client. Interop: pycomm3 in docker (`--network host`), tagged `:interop`.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. No mocks — loopback tests use the real scanner or raw `gen_tcp`/`gen_udp` clients speaking real bytes.
- `decode`-side functions never raise on network input; malformed input maps to the correct encap status (0x0001 invalid command, 0x0003 malformed CPF, 0x0064 invalid session handle) or CIP status (0x04 path, 0x05 unknown destination, 0x08 unsupported service, 0x0E not settable, 0x13 not enough data).
- One `SessionHandler` crash must never take down the listener (DynamicSupervisor, `restart: :temporary`).
- `mix format` before every commit. One CHANGELOG line per commit: `[Type] What changed`, ≤100 chars, appended at the bottom of the current version's list.
- TDD: failing test first, watch it fail, implement, watch it pass, commit.
- Phase 1+2 suites (111 tests + 3 properties) stay green throughout.

## File Structure

```
eipex/
├── lib/eipex/
│   ├── encap.ex                          # Task 1: encode {:unknown, code} replies
│   ├── cip/connection_manager.ex         # Task 1: decode_unconnected_send/1
│   ├── scanner.ex                        # Task 9: deferred hardening
│   └── adapter/
│       ├── adapter.ex (Eipex.Adapter)    # Task 2: owner GenServer + public API
│       ├── config.ex                     # Task 2: %Config{} passed to every handler
│       ├── assembly_store.ex             # Task 2: instance => %{kind, size, data}
│       ├── handler.ex                    # Task 4: app behaviour + Default impl
│       ├── message_router.ex             # Task 3: dispatch/3 (pure)
│       ├── object.ex                     # Task 3: CIP class behaviour
│       ├── object/identity.ex            # Task 3
│       ├── object/message_router_object.ex # Task 3 (stub, class 0x02)
│       ├── object/assembly.ex            # Task 4
│       ├── object/connection_manager.ex  # Task 5 (Unconnected Send target side)
│       ├── object/tcp_ip_interface.ex    # Task 5
│       ├── object/ethernet_link.ex       # Task 5
│       ├── listener.ex                   # Task 6
│       ├── session_handler.ex            # Task 6
│       └── discovery.ex                  # Task 7 (UDP responder)
├── test/eipex/adapter/…                  # mirrors lib
├── test/interop/pycomm3_test.exs         # Task 8
└── interop/pycomm3/check_adapter.py      # Task 8
```

**Public API after this phase:**

```elixir
{:ok, adapter} = Eipex.Adapter.start_link(
  identity: [vendor_id: 1234, device_type: 0x0C, product_code: 1,
             revision: {1, 0}, serial_number: 42, product_name: "Eipex Adapter"],
  assemblies: [
    input:  [instance: 100, size: 32],
    output: [instance: 150, size: 32],
    config: [instance: 151, size: 10]
  ],
  handler: MyApp.EipHandler,          # optional, defaults to permissive Default
  objects: [{0x64, MyApp.Custom}],    # optional extra CIP classes
  port: 44_818,                       # 0 = ephemeral (tests); Adapter.port/1 reads it
  inactivity_timeout: 120_000,
  discovery: false                    # or [port: 44_818, delay: {0, 500}]
)

{:ok, port}  = Eipex.Adapter.port(adapter)
:ok          = Eipex.Adapter.write_assembly(adapter, 100, <<...32 bytes...>>)
{:ok, data}  = Eipex.Adapter.read_assembly(adapter, 150)
```

```elixir
defmodule Eipex.Adapter.Handler do
  @callback after_assembly_write(instance :: non_neg_integer(), data :: binary(), ctx :: map()) ::
              :ok | {:error, cip_status :: byte()}
  @callback before_assembly_read(instance :: non_neg_integer(), ctx :: map()) ::
              {:ok, binary()} | :keep
  @callback reset(type :: byte()) :: :ok | {:error, cip_status :: byte()}
  # `use Eipex.Adapter.Handler` provides permissive defaults, all overridable.
end

defmodule Eipex.Adapter.Object do
  @callback handle_service(service :: byte(), instance :: non_neg_integer(),
              path_rest :: [Eipex.CIP.Path.segment()], data :: binary(), ctx :: map()) ::
              {:reply, binary()} | {:error, status :: byte(), extended :: [non_neg_integer()]}
  # ctx: %{config: %Config{}, store: pid, handler: module}
end
```

Connection semantics in this phase: UCMM only. `Forward Open`/`Large Forward Open`/`Forward Close` (0x54/0x5B/0x4E) answer general status 0x08 (service not supported) until Phase 4. `SendUnitData` frames answer encap status 0x0001.

---

### Task 1: Codec additions (decode Unconnected Send + unknown-command replies)

**Files:**
- Modify: `lib/eipex/cip/connection_manager.ex`
- Modify: `lib/eipex/encap.ex`
- Test: `test/eipex/cip/connection_manager_test.exs`, `test/eipex/encap_test.exs` (append)

**Interfaces:**
- Consumes: existing codecs.
- Produces:
  - `Eipex.CIP.ConnectionManager.decode_unconnected_send(data :: binary) :: {:ok, %{priority_time_tick: byte, timeout_ticks: byte, embedded: binary, route: binary}} | {:error, :malformed_unconnected_send}` — inverse of `encode_unconnected_send/3`; handles the odd-size pad byte.
  - `Eipex.Encap.encode/1` accepts `%Encap{command: {:unknown, code}}` and emits `code::16-little` — needed so the adapter can echo unknown commands back with status 0x0001.

- [ ] **Step 1: Write the failing tests**

Append to `test/eipex/cip/connection_manager_test.exs`:

```elixir
  test "unconnected send round-trips through decode (odd and even embedded)" do
    for data <- [<<1, 2, 3>>, <<1, 2>>] do
      embedded = Eipex.CIP.MessageRouter.encode_request(0x4C, [symbolic: "abc"], data)
      request = CM.encode_unconnected_send(embedded, [{:port, 1, 0}], timeout_ticks: 7)
      {:ok, %{service: 0x52, data: payload}} = Eipex.CIP.MessageRouter.decode_request(request)

      assert {:ok, %{embedded: ^embedded, route: <<0x01, 0x00>>,
                     priority_time_tick: 0x0A, timeout_ticks: 7}} =
               CM.decode_unconnected_send(payload)
    end
  end

  test "decode_unconnected_send rejects truncated payloads" do
    assert {:error, :malformed_unconnected_send} = CM.decode_unconnected_send(<<1, 2, 9::16-little, 1>>)
    assert {:error, :malformed_unconnected_send} = CM.decode_unconnected_send(<<1>>)
  end
```

Append to `test/eipex/encap_test.exs`:

```elixir
  test "encode emits unknown commands verbatim (for status-0x0001 replies)" do
    frame = %Encap{command: {:unknown, 0xABCD}, session_handle: 7, status: 0x0001}
    encoded = Encap.encode(frame)
    assert <<0xABCD::16-little, 0::16-little, 7::32-little, 0x0001::32-little, _::binary>> = encoded
    assert {:ok, ^frame, <<>>} = Encap.decode(encoded)
  end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/connection_manager_test.exs test/eipex/encap_test.exs`
Expected: FAIL — `decode_unconnected_send/1` undefined; encode raises `KeyError` on the tuple command.

- [ ] **Step 3: Implement**

In `Eipex.CIP.ConnectionManager`, after `encode_unconnected_send/3`:

```elixir
  @spec decode_unconnected_send(binary()) ::
          {:ok, %{priority_time_tick: byte(), timeout_ticks: byte(),
                  embedded: binary(), route: binary()}}
          | {:error, :malformed_unconnected_send}
  def decode_unconnected_send(<<ptt, ticks, size::16-little,
                                embedded::binary-size(size), rest::binary>>) do
    pad = rem(size, 2)

    with <<_::binary-size(pad), route_words, _reserved,
           route::binary-size(route_words * 2)>> <- rest do
      {:ok, %{priority_time_tick: ptt, timeout_ticks: ticks,
              embedded: embedded, route: route}}
    else
      _ -> {:error, :malformed_unconnected_send}
    end
  end

  def decode_unconnected_send(_), do: {:error, :malformed_unconnected_send}
```

In `Eipex.Encap.encode/1`, change the command-code resolution so a tuple passes through:

```elixir
  def encode(%__MODULE__{} = frame) do
    code = command_code(frame.command)
    ...
  end

  defp command_code({:unknown, code}) when code in 0..0xFFFF, do: code
  defp command_code(command), do: Keyword.fetch!(@commands, command)
```

(The `decode` side already produces `{:unknown, code}` from the Phase 1 final-review fix; keep the `byte_size(frame.data) <= 0xFFFF` guard as is.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/connection_manager_test.exs test/eipex/encap_test.exs`
Expected: PASS. Full `mix test` green (114 hermetic tests + 3 properties).

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Unconnected Send decode and unknown-command encapsulation replies`

```bash
mix format && git add -A && git commit -m "feat: adapter-side codec additions"
```

---

### Task 2: Adapter skeleton — Config, AssemblyStore, owner process

**Files:**
- Create: `lib/eipex/adapter/config.ex`, `lib/eipex/adapter/assembly_store.ex`, `lib/eipex/adapter/adapter.ex`
- Test: `test/eipex/adapter/assembly_store_test.exs`, `test/eipex/adapter/adapter_test.exs`

**Interfaces:**
- Consumes: `%Eipex.Identity{}` (Phase 1).
- Produces:
  - `%Eipex.Adapter.Config{identity: %Eipex.Identity{}, objects: %{class => module}, handler: module, store: pid, inactivity_timeout: non_neg_integer, network: map}`
  - `Eipex.Adapter.AssemblyStore.start_link(assemblies_keyword) :: {:ok, pid}` with `read(store, instance) :: {:ok, binary} | {:error, :no_assembly}`, `write(store, instance, data) :: :ok | {:error, :no_assembly | :size_mismatch}`, `info(store, instance) :: {:ok, %{kind: :input | :output | :config, size: pos_integer}} | {:error, :no_assembly}`. Buffers start zero-filled.
  - `Eipex.Adapter.start_link(opts)` — this task: validates opts, builds `%Config{}`, starts store + DynamicSupervisor (Listener/Discovery come in Tasks 6-7 — init written so those slots are added there). Public: `read_assembly/2`, `write_assembly/3` (delegating to the store), `config/1` (test introspection).

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/assembly_store_test.exs`:

```elixir
defmodule Eipex.Adapter.AssemblyStoreTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.AssemblyStore

  defp start_store do
    {:ok, store} =
      AssemblyStore.start_link(
        input: [instance: 100, size: 4],
        output: [instance: 150, size: 4],
        config: [instance: 151, size: 2]
      )

    store
  end

  test "buffers start zero-filled with the declared size" do
    store = start_store()
    assert {:ok, <<0, 0, 0, 0>>} = AssemblyStore.read(store, 100)
    assert {:ok, %{kind: :config, size: 2}} = AssemblyStore.info(store, 151)
  end

  test "write requires the exact declared size" do
    store = start_store()
    assert :ok = AssemblyStore.write(store, 150, <<1, 2, 3, 4>>)
    assert {:ok, <<1, 2, 3, 4>>} = AssemblyStore.read(store, 150)
    assert {:error, :size_mismatch} = AssemblyStore.write(store, 150, <<1, 2>>)
  end

  test "unknown instances error" do
    store = start_store()
    assert {:error, :no_assembly} = AssemblyStore.read(store, 99)
    assert {:error, :no_assembly} = AssemblyStore.write(store, 99, <<1>>)
    assert {:error, :no_assembly} = AssemblyStore.info(store, 99)
  end
end
```

`test/eipex/adapter/adapter_test.exs`:

```elixir
defmodule Eipex.AdapterTest do
  use ExUnit.Case

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  defp start_adapter(extra \\ []) do
    {:ok, pid} =
      Eipex.Adapter.start_link(
        [identity: @identity,
         assemblies: [input: [instance: 100, size: 4], output: [instance: 150, size: 4],
                      config: [instance: 151, size: 2]],
         port: 0] ++ extra
      )

    pid
  end

  test "boots and exposes assembly access" do
    pid = start_adapter()
    assert :ok = Eipex.Adapter.write_assembly(pid, 100, <<9, 9, 9, 9>>)
    assert {:ok, <<9, 9, 9, 9>>} = Eipex.Adapter.read_assembly(pid, 100)
  end

  test "builds the config with identity and default objects" do
    pid = start_adapter()
    config = Eipex.Adapter.config(pid)

    assert %Eipex.Identity{vendor_id: 0x4D, product_name: "Eipex Adapter"} = config.identity
    assert %{0x01 => _, 0x02 => _, 0x04 => _, 0x06 => _, 0xF5 => _, 0xF6 => _} = config.objects
    assert config.inactivity_timeout == 120_000
  end

  test "user objects merge over defaults and identity is mandatory" do
    defmodule FakeObject do
    end

    pid = start_adapter(objects: [{0x64, FakeObject}])
    assert Eipex.Adapter.config(pid).objects[0x64] == FakeObject

    Process.flag(:trap_exit, true)
    assert {:error, _} = Eipex.Adapter.start_link(assemblies: [], port: 0)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/`
Expected: FAIL — modules undefined.

- [ ] **Step 3: Implement the three modules**

`lib/eipex/adapter/config.ex`:

```elixir
defmodule Eipex.Adapter.Config do
  @moduledoc """
  Immutable adapter configuration handed to every session handler and
  CIP object dispatch: identity, object dispatch table, application
  handler module, assembly store, timeouts and network attributes.
  """

  defstruct identity: nil,
            objects: %{},
            handler: nil,
            store: nil,
            inactivity_timeout: 120_000,
            network: %{}

  @type t :: %__MODULE__{}
end
```

`lib/eipex/adapter/assembly_store.ex`:

```elixir
defmodule Eipex.Adapter.AssemblyStore do
  @moduledoc """
  Owns the assembly buffers: `instance => %{kind, size, data}`.
  Explicit messaging reads/writes go through here; the application refreshes
  produced data with `write/3` and consumes received data with `read/2`.
  """

  use GenServer

  @type kind :: :input | :output | :config

  def start_link(assemblies), do: GenServer.start_link(__MODULE__, assemblies)

  @spec read(GenServer.server(), non_neg_integer()) :: {:ok, binary()} | {:error, :no_assembly}
  def read(store, instance), do: GenServer.call(store, {:read, instance})

  @spec write(GenServer.server(), non_neg_integer(), binary()) ::
          :ok | {:error, :no_assembly | :size_mismatch}
  def write(store, instance, data), do: GenServer.call(store, {:write, instance, data})

  @spec info(GenServer.server(), non_neg_integer()) ::
          {:ok, %{kind: kind(), size: pos_integer()}} | {:error, :no_assembly}
  def info(store, instance), do: GenServer.call(store, {:info, instance})

  @impl true
  def init(assemblies) do
    buffers =
      for {kind, spec} <- assemblies, into: %{} do
        instance = Keyword.fetch!(spec, :instance)
        size = Keyword.fetch!(spec, :size)
        {instance, %{kind: kind, size: size, data: :binary.copy(<<0>>, size)}}
      end

    {:ok, buffers}
  end

  @impl true
  def handle_call({:read, instance}, _from, buffers) do
    case buffers do
      %{^instance => %{data: data}} -> {:reply, {:ok, data}, buffers}
      _ -> {:reply, {:error, :no_assembly}, buffers}
    end
  end

  def handle_call({:write, instance, data}, _from, buffers) do
    case buffers do
      %{^instance => %{size: size} = buffer} when byte_size(data) == size ->
        {:reply, :ok, %{buffers | instance => %{buffer | data: data}}}

      %{^instance => _} ->
        {:reply, {:error, :size_mismatch}, buffers}

      _ ->
        {:reply, {:error, :no_assembly}, buffers}
    end
  end

  def handle_call({:info, instance}, _from, buffers) do
    case buffers do
      %{^instance => %{kind: kind, size: size}} -> {:reply, {:ok, %{kind: kind, size: size}}, buffers}
      _ -> {:reply, {:error, :no_assembly}, buffers}
    end
  end
end
```

`lib/eipex/adapter/adapter.ex`:

```elixir
defmodule Eipex.Adapter do
  @moduledoc """
  EtherNet/IP adapter (target) for explicit messaging.

  One process tree per adapter: this GenServer owns (links) the assembly
  store, the session-handler supervisor and the TCP listener. If any of
  them dies the whole adapter dies and the owning application's supervisor
  decides — mirroring the scanner's no-magic-recovery contract.
  """

  use GenServer

  alias Eipex.Adapter.{AssemblyStore, Config}
  alias Eipex.Identity

  @default_objects %{
    0x01 => Eipex.Adapter.Object.Identity,
    0x02 => Eipex.Adapter.Object.MessageRouterObject,
    0x04 => Eipex.Adapter.Object.Assembly,
    0x06 => Eipex.Adapter.Object.ConnectionManager,
    0xF5 => Eipex.Adapter.Object.TcpIpInterface,
    0xF6 => Eipex.Adapter.Object.EthernetLink
  }

  # -- Public API --------------------------------------------------------------

  def start_link(opts) do
    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, :not_listening}
  def port(server), do: GenServer.call(server, :port)

  @spec read_assembly(GenServer.server(), non_neg_integer()) ::
          {:ok, binary()} | {:error, term()}
  def read_assembly(server, instance), do: GenServer.call(server, {:read_assembly, instance})

  @spec write_assembly(GenServer.server(), non_neg_integer(), binary()) ::
          :ok | {:error, term()}
  def write_assembly(server, instance, data),
    do: GenServer.call(server, {:write_assembly, instance, data})

  @doc false
  def config(server), do: GenServer.call(server, :config)

  # -- GenServer ---------------------------------------------------------------

  @impl true
  def init(opts) do
    with {:ok, identity} <- build_identity(Keyword.get(opts, :identity)),
         {:ok, store} <- AssemblyStore.start_link(Keyword.get(opts, :assemblies, [])),
         {:ok, sessions_sup} <- DynamicSupervisor.start_link(strategy: :one_for_one) do
      config = %Config{
        identity: identity,
        objects: Map.merge(@default_objects, Map.new(Keyword.get(opts, :objects, []))),
        handler: Keyword.get(opts, :handler, Eipex.Adapter.Handler.Default),
        store: store,
        inactivity_timeout: Keyword.get(opts, :inactivity_timeout, 120_000),
        network: Map.new(Keyword.get(opts, :network, []))
      }

      # Listener (Task 6) and Discovery (Task 7) start here once they exist.
      {:ok, %{config: config, sessions_sup: sessions_sup, listener: nil, opts: opts}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state) do
    # Task 6 replaces this clause with a Listener.port/1 lookup once the
    # listener exists; referencing the module now would warn at compile time.
    {:reply, {:error, :not_listening}, state}
  end

  def handle_call({:read_assembly, instance}, _from, state) do
    {:reply, AssemblyStore.read(state.config.store, instance), state}
  end

  def handle_call({:write_assembly, instance, data}, _from, state) do
    {:reply, AssemblyStore.write(state.config.store, instance, data), state}
  end

  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  # -- Option handling -----------------------------------------------------------

  defp build_identity(nil), do: {:error, :missing_identity}

  defp build_identity(opts) do
    {:ok,
     %Identity{
       vendor_id: Keyword.fetch!(opts, :vendor_id),
       device_type: Keyword.get(opts, :device_type, 0x0C),
       product_code: Keyword.fetch!(opts, :product_code),
       revision: Keyword.get(opts, :revision, {1, 0}),
       serial_number: Keyword.get(opts, :serial_number, 0),
       product_name: Keyword.fetch!(opts, :product_name),
       state: 3
     }}
  end
end
```

Note: the object modules referenced by `@default_objects` do not exist yet
(Tasks 3-5). Module attributes hold atoms — nothing is called until dispatch —
so this compiles and boots; the config test only asserts map keys.

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/`
Expected: PASS. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter skeleton: config, assembly store and owner process`

```bash
mix format && git add -A && git commit -m "feat: adapter skeleton"
```

---

### Task 3: Message Router dispatch + Object/Handler behaviours + Identity object

**Files:**
- Create: `lib/eipex/adapter/message_router.ex`, `lib/eipex/adapter/object.ex`, `lib/eipex/adapter/handler.ex`, `lib/eipex/adapter/object/identity.ex`, `lib/eipex/adapter/object/message_router_object.ex`
- Test: `test/eipex/adapter/message_router_test.exs`

**Interfaces:**
- Consumes: `Eipex.CIP.MessageRouter` (as `MR`), `Eipex.CIP.Path`, `%Config{}` (Task 2).
- Produces:
  - `Eipex.Adapter.MessageRouter.dispatch(config, mr_request :: binary) :: mr_response :: binary` — pure; never raises on network input; a crashing object module maps to general status 0x1F (vendor-specific error) with a `Logger.error`.
  - `Eipex.Adapter.Object` behaviour: `handle_service(service, instance, path_rest, data, ctx) :: {:reply, binary} | {:raw, mr_response_binary} | {:error, status, extended}`. `{:raw, _}` sends a complete pre-encoded MR response (needed by Unconnected Send, whose reply IS the embedded response). `ctx = %{config, store, handler}`.
  - `Eipex.Adapter.Handler` behaviour + `use` defaults + `Eipex.Adapter.Handler.Default` (see the header section for callbacks).
  - `Object.Identity`: Get_Attributes_All (0x01) → attrs 1-7 concatenated; Get_Attribute_Single (0x0E) attrs 1-7; Reset (0x05) → `handler.reset(type)`. Unknown attr → 0x14; instance ≠ 1 → 0x05; other services → 0x08.
  - `Object.MessageRouterObject` (class 0x02 stub): any service → 0x08 on instance 1, else 0x05 (Multiple Service Packet server-side is deliberately deferred; documented).
  - Status mapping in dispatch: undecodable request → response with service 0x00, status 0x13; malformed path → 0x04; path without leading class (e.g. symbolic) → 0x05; unregistered class → 0x05.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/message_router_test.exs`:

```elixir
defmodule Eipex.Adapter.MessageRouterTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{Config, MessageRouter}
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.Identity

  defmodule RejectingHandler do
    use Eipex.Adapter.Handler
    def reset(1), do: {:error, 0x0C}
    def reset(_), do: :ok
  end

  defmodule CrashingObject do
    @behaviour Eipex.Adapter.Object
    def handle_service(_, _, _, _, _), do: raise("boom")
  end

  defp config(overrides \\ []) do
    identity = %Identity{vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
                         revision: {1, 2}, serial_number: 0x99,
                         product_name: "Eipex Adapter", status: 0, state: 3}

    struct!(
      %Config{identity: identity,
              objects: %{0x01 => Eipex.Adapter.Object.Identity,
                         0x02 => Eipex.Adapter.Object.MessageRouterObject,
                         0x64 => CrashingObject},
              handler: Eipex.Adapter.Handler.Default},
      overrides
    )
  end

  defp roundtrip(config, service, path, data \\ <<>>) do
    request = MR.encode_request(service, path, data)
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "get_attribute_single reads identity attributes" do
    assert %{status_name: :success, data: <<0x4D, 0x00>>} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 1)

    assert %{data: <<1, 2>>} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 4)

    assert %{data: <<13, "Eipex Adapter">>} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 7)
  end

  test "get_attributes_all concatenates attributes 1..7" do
    assert %{status_name: :success, data: data} =
             roundtrip(config(), 0x01, class: 0x01, instance: 1)

    assert data ==
             <<0x4D::16-little, 0x0C::16-little, 0x77::16-little, 1, 2,
               0::16-little, 0x99::32-little, 13, "Eipex Adapter">>
  end

  test "reset delegates to the handler" do
    assert %{status_name: :success} = roundtrip(config(), 0x05, [class: 0x01, instance: 1])

    cfg = config(handler: RejectingHandler)
    assert %{status: 0x0C} = roundtrip(cfg, 0x05, [class: 0x01, instance: 1], <<1>>)
  end

  test "CIP error statuses for bad addressing" do
    assert %{status_name: :attribute_not_supported} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 99)

    assert %{status_name: :path_destination_unknown} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 9, attribute: 1)

    assert %{status_name: :path_destination_unknown} =
             roundtrip(config(), 0x0E, class: 0x77, instance: 1, attribute: 1)

    assert %{status_name: :service_not_supported} =
             roundtrip(config(), 0x32, class: 0x01, instance: 1)

    assert %{status_name: :service_not_supported} =
             roundtrip(config(), 0x0A, class: 0x02, instance: 1)
  end

  test "symbolic paths are unknown destinations on an adapter" do
    assert %{status_name: :path_destination_unknown} =
             roundtrip(config(), 0x4C, [symbolic: "MyTag"], <<1::16-little>>)
  end

  test "malformed requests and paths degrade to error responses, never raise" do
    {:ok, resp} = config() |> MessageRouter.dispatch(<<0x0E, 0x09, 0x91>>) |> MR.decode_response()
    assert resp.status_name == :not_enough_data

    bad_path = <<0x0E, 0x01, 0xFF, 0x00>>
    {:ok, resp2} = config() |> MessageRouter.dispatch(bad_path) |> MR.decode_response()
    assert resp2.status_name == :path_segment_error
  end

  test "a crashing object maps to vendor-specific error, not a crash" do
    import ExUnit.CaptureLog

    log =
      capture_log(fn ->
        assert %{status_name: :vendor_specific_error} =
                 roundtrip(config(), 0x0E, class: 0x64, instance: 1, attribute: 1)
      end)

    assert log =~ "boom"
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/message_router_test.exs`
Expected: FAIL — modules undefined.

- [ ] **Step 3: Implement**

`lib/eipex/adapter/handler.ex`:

```elixir
defmodule Eipex.Adapter.Handler do
  @moduledoc """
  Application-side callbacks for the adapter. `use Eipex.Adapter.Handler`
  provides permissive defaults; override what you need. Returning
  `{:error, cip_status}` from a callback surfaces that status to the
  requesting scanner.
  """

  @callback after_assembly_write(instance :: non_neg_integer(), data :: binary(), ctx :: map()) ::
              :ok | {:error, byte()}
  @callback before_assembly_read(instance :: non_neg_integer(), ctx :: map()) ::
              {:ok, binary()} | :keep
  @callback reset(type :: byte()) :: :ok | {:error, byte()}

  defmacro __using__(_opts) do
    quote do
      @behaviour Eipex.Adapter.Handler

      def after_assembly_write(_instance, _data, _ctx), do: :ok
      def before_assembly_read(_instance, _ctx), do: :keep
      def reset(_type), do: :ok

      defoverridable after_assembly_write: 3, before_assembly_read: 2, reset: 1
    end
  end
end

defmodule Eipex.Adapter.Handler.Default do
  @moduledoc false
  use Eipex.Adapter.Handler
end
```

`lib/eipex/adapter/object.ex`:

```elixir
defmodule Eipex.Adapter.Object do
  @moduledoc """
  Behaviour for CIP object classes served by the adapter's Message Router.

  Return `{:reply, data}` for a success response, `{:error, status, extended}`
  for a CIP error, or `{:raw, response}` when the module already built the
  complete Message Router response (Unconnected Send replies with the
  embedded response verbatim).
  """

  @callback handle_service(service :: byte(), instance :: non_neg_integer(),
              path_rest :: [Eipex.CIP.Path.segment()], data :: binary(), ctx :: map()) ::
              {:reply, binary()} | {:raw, binary()} | {:error, byte(), [non_neg_integer()]}
end
```

`lib/eipex/adapter/message_router.ex`:

```elixir
defmodule Eipex.Adapter.MessageRouter do
  @moduledoc """
  Adapter-side dispatch: Message Router request binary in, response binary
  out. Routes by class code to `Eipex.Adapter.Object` modules. Pure — never
  raises on network input; object crashes map to status 0x1F.
  """

  require Logger

  alias Eipex.Adapter.Config
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  @spec dispatch(Config.t(), binary()) :: binary()
  def dispatch(%Config{} = config, request) do
    case MR.decode_request(request) do
      {:ok, %{service: service, path: path, data: data}} ->
        route(config, service, path, data)

      {:error, _} ->
        MR.encode_response(0x00, 0x13)
    end
  end

  defp route(config, service, path, data) do
    case Path.decode(path) do
      {:ok, [{:class, class} | rest]} ->
        {instance, path_rest} = pop_instance(rest)
        invoke(config, class, service, instance, path_rest, data)

      {:ok, _segments} ->
        MR.encode_response(service, 0x05)

      {:error, _} ->
        MR.encode_response(service, 0x04)
    end
  end

  defp invoke(config, class, service, instance, path_rest, data) do
    case Map.fetch(config.objects, class) do
      {:ok, module} ->
        ctx = %{config: config, store: config.store, handler: config.handler}

        try do
          case module.handle_service(service, instance, path_rest, data, ctx) do
            {:reply, reply_data} -> MR.encode_response(service, 0x00, data: reply_data)
            {:raw, response} -> response
            {:error, status, extended} -> MR.encode_response(service, status, extended: extended)
          end
        rescue
          exception ->
            Logger.error(
              "CIP object #{inspect(module)} crashed: #{Exception.message(exception)}"
            )

            MR.encode_response(service, 0x1F)
        end

      :error ->
        MR.encode_response(service, 0x05)
    end
  end

  defp pop_instance([{:instance, instance} | rest]), do: {instance, rest}
  defp pop_instance(rest), do: {0, rest}
end
```

`lib/eipex/adapter/object/identity.ex`:

```elixir
defmodule Eipex.Adapter.Object.Identity do
  @moduledoc "Identity object (class 0x01): attributes 1-7 and Reset."

  @behaviour Eipex.Adapter.Object

  @get_attributes_all 0x01
  @reset 0x05
  @get_attribute_single 0x0E

  @impl true
  def handle_service(@get_attributes_all, 1, [], <<>>, ctx) do
    {:reply, Enum.map_join(1..7, &attribute(&1, ctx.config.identity))}
  end

  def handle_service(@get_attribute_single, 1, [{:attribute, n}], <<>>, ctx) do
    case attribute(n, ctx.config.identity) do
      nil -> {:error, 0x14, []}
      data -> {:reply, data}
    end
  end

  def handle_service(@reset, 1, [], data, ctx) do
    type =
      case data do
        <<>> -> 0
        <<t, _::binary>> -> t
      end

    case ctx.handler.reset(type) do
      :ok -> {:reply, <<>>}
      {:error, status} -> {:error, status, []}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp attribute(1, id), do: <<id.vendor_id::16-little>>
  defp attribute(2, id), do: <<id.device_type::16-little>>
  defp attribute(3, id), do: <<id.product_code::16-little>>
  defp attribute(4, %{revision: {major, minor}}), do: <<major, minor>>
  defp attribute(5, id), do: <<id.status::16-little>>
  defp attribute(6, id), do: <<id.serial_number::32-little>>
  defp attribute(7, id), do: <<byte_size(id.product_name), id.product_name::binary>>
  defp attribute(_, _), do: nil
end
```

`lib/eipex/adapter/object/message_router_object.ex`:

```elixir
defmodule Eipex.Adapter.Object.MessageRouterObject do
  @moduledoc """
  Message Router object (class 0x02) stub: the routing itself lives in
  `Eipex.Adapter.MessageRouter`; requests addressed to this class (e.g.
  Multiple Service Packet, deferred) answer 0x08.
  """

  @behaviour Eipex.Adapter.Object

  @impl true
  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/message_router_test.exs`
Expected: PASS, 8 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter message router dispatch, object/handler behaviours and Identity object`

```bash
mix format && git add -A && git commit -m "feat: adapter dispatch and identity object"
```

---

### Task 4: Assembly object

**Files:**
- Create: `lib/eipex/adapter/object/assembly.ex`
- Test: `test/eipex/adapter/object/assembly_test.exs`

**Interfaces:**
- Consumes: `AssemblyStore` (Task 2), `Handler` (Task 3), dispatch ctx.
- Produces: `Object.Assembly` — Get_Attribute_Single attr 3 (data; `:input` reads go through `handler.before_assembly_read/2` first, `{:ok, fresh}` refreshes the store) and attr 4 (`<<size::16-little>>`); Set_Attribute_Single attr 3 (rejects `:input` with 0x0E; wrong size → 0x13 short / 0x15 long; then `handler.after_assembly_write/3` — `{:error, status}` rejects without storing; then store). Unknown instance → 0x05; unknown attr → 0x14; other services → 0x08.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/object/assembly_test.exs`:

```elixir
defmodule Eipex.Adapter.Object.AssemblyTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{AssemblyStore, Config, MessageRouter}
  alias Eipex.CIP.MessageRouter, as: MR

  defmodule PickyHandler do
    use Eipex.Adapter.Handler
    # config assembly (151) only accepts values starting with 0xA5
    def after_assembly_write(151, <<0xA5, _::binary>>, _ctx), do: :ok
    def after_assembly_write(151, _data, _ctx), do: {:error, 0x09}
    def after_assembly_write(_instance, _data, _ctx), do: :ok

    def before_assembly_read(100, _ctx), do: {:ok, <<9, 9, 9, 9>>}
    def before_assembly_read(_instance, _ctx), do: :keep
  end

  defp config(handler \\ Eipex.Adapter.Handler.Default) do
    {:ok, store} =
      AssemblyStore.start_link(
        input: [instance: 100, size: 4],
        output: [instance: 150, size: 4],
        config: [instance: 151, size: 2]
      )

    %Config{identity: nil, handler: handler, store: store,
            objects: %{0x04 => Eipex.Adapter.Object.Assembly}}
  end

  defp roundtrip(config, service, path, data \\ <<>>) do
    request = MR.encode_request(service, path, data)
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "reads data and size attributes" do
    cfg = config()

    assert %{status_name: :success, data: <<0, 0, 0, 0>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 3)

    assert %{data: <<4::16-little>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 4)
  end

  test "writes the output assembly and reads it back" do
    cfg = config()

    assert %{status_name: :success} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2, 3, 4>>)

    assert %{data: <<1, 2, 3, 4>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 3)
  end

  test "input assemblies are not settable over the network" do
    assert %{status_name: :attribute_not_settable} =
             roundtrip(config(), 0x10, [class: 0x04, instance: 100, attribute: 3], <<1, 2, 3, 4>>)
  end

  test "size mismatches map to not-enough / too-much data" do
    cfg = config()

    assert %{status_name: :not_enough_data} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2>>)

    assert %{status_name: :too_much_data} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2, 3, 4, 5>>)
  end

  test "handler can reject writes; store stays untouched" do
    cfg = config(PickyHandler)

    assert %{status_name: :invalid_attribute_value} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 151, attribute: 3], <<0xFF, 0x00>>)

    assert {:ok, <<0, 0>>} = AssemblyStore.read(cfg.store, 151)

    assert %{status_name: :success} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 151, attribute: 3], <<0xA5, 0x01>>)

    assert {:ok, <<0xA5, 0x01>>} = AssemblyStore.read(cfg.store, 151)
  end

  test "handler refreshes input assemblies before reads" do
    cfg = config(PickyHandler)

    assert %{status_name: :success, data: <<9, 9, 9, 9>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 100, attribute: 3)

    assert {:ok, <<9, 9, 9, 9>>} = AssemblyStore.read(cfg.store, 100)
  end

  test "unknown instances and attributes" do
    cfg = config()

    assert %{status_name: :path_destination_unknown} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 99, attribute: 3)

    assert %{status_name: :attribute_not_supported} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 9)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/object/assembly_test.exs`
Expected: FAIL — `Eipex.Adapter.Object.Assembly` undefined.

- [ ] **Step 3: Implement `Object.Assembly`**

`lib/eipex/adapter/object/assembly.ex`:

```elixir
defmodule Eipex.Adapter.Object.Assembly do
  @moduledoc """
  Assembly object (class 0x04). Attribute 3 is the data buffer, attribute 4
  its size. `:input` (produced) assemblies refresh through the application
  handler before reads and reject network writes; `:output`/`:config`
  writes validate size, then the handler, then land in the store.
  """

  @behaviour Eipex.Adapter.Object

  alias Eipex.Adapter.AssemblyStore

  @get_attribute_single 0x0E
  @set_attribute_single 0x10

  @impl true
  def handle_service(@get_attribute_single, instance, [{:attribute, 3}], <<>>, ctx) do
    case AssemblyStore.info(ctx.store, instance) do
      {:ok, %{kind: :input}} -> {:reply, refreshed_read(instance, ctx)}
      {:ok, _} -> read(instance, ctx)
      {:error, :no_assembly} -> {:error, 0x05, []}
    end
  end

  def handle_service(@get_attribute_single, instance, [{:attribute, 4}], <<>>, ctx) do
    case AssemblyStore.info(ctx.store, instance) do
      {:ok, %{size: size}} -> {:reply, <<size::16-little>>}
      {:error, :no_assembly} -> {:error, 0x05, []}
    end
  end

  def handle_service(@get_attribute_single, instance, [{:attribute, _}], <<>>, ctx) do
    with {:ok, _} <- AssemblyStore.info(ctx.store, instance) do
      {:error, 0x14, []}
    else
      _ -> {:error, 0x05, []}
    end
  end

  def handle_service(@set_attribute_single, instance, [{:attribute, 3}], data, ctx) do
    case AssemblyStore.info(ctx.store, instance) do
      {:ok, %{kind: :input}} ->
        {:error, 0x0E, []}

      {:ok, %{size: size}} when byte_size(data) < size ->
        {:error, 0x13, []}

      {:ok, %{size: size}} when byte_size(data) > size ->
        {:error, 0x15, []}

      {:ok, _} ->
        case ctx.handler.after_assembly_write(instance, data, ctx) do
          :ok ->
            :ok = AssemblyStore.write(ctx.store, instance, data)
            {:reply, <<>>}

          {:error, status} ->
            {:error, status, []}
        end

      {:error, :no_assembly} ->
        {:error, 0x05, []}
    end
  end

  def handle_service(@set_attribute_single, instance, [{:attribute, _}], _data, ctx) do
    with {:ok, _} <- AssemblyStore.info(ctx.store, instance) do
      {:error, 0x14, []}
    else
      _ -> {:error, 0x05, []}
    end
  end

  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x08, []}

  defp read(instance, ctx) do
    {:ok, data} = AssemblyStore.read(ctx.store, instance)
    {:reply, data}
  end

  defp refreshed_read(instance, ctx) do
    case ctx.handler.before_assembly_read(instance, ctx) do
      {:ok, fresh} ->
        case AssemblyStore.write(ctx.store, instance, fresh) do
          :ok ->
            fresh

          {:error, _} ->
            {:ok, stored} = AssemblyStore.read(ctx.store, instance)
            stored
        end

      :keep ->
        {:ok, stored} = AssemblyStore.read(ctx.store, instance)
        stored
    end
  end
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/object/assembly_test.exs`
Expected: PASS, 7 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Assembly object with handler-mediated reads and writes`

```bash
mix format && git add -A && git commit -m "feat: adapter assembly object"
```

---

### Task 5: Connection Manager, TCP/IP Interface and Ethernet Link objects

**Files:**
- Create: `lib/eipex/adapter/object/connection_manager.ex`, `lib/eipex/adapter/object/tcp_ip_interface.ex`, `lib/eipex/adapter/object/ethernet_link.ex`
- Test: `test/eipex/adapter/object/network_objects_test.exs`

**Interfaces:**
- Consumes: `Eipex.CIP.ConnectionManager.decode_unconnected_send/1` (Task 1), `Eipex.Adapter.MessageRouter.dispatch/2` (Task 3, re-entered for the embedded request), `config.network` map (Task 2).
- Produces:
  - `Object.ConnectionManager` (class 0x06): Unconnected Send (0x52) → decode, accept a single-hop route unconditionally (this device IS the target), dispatch the embedded request locally, return `{:raw, embedded_response}` (the UCMM reply to an Unconnected Send is the embedded service's response verbatim); malformed → 0x13. Forward Open/Large/Close (0x54/0x5B/0x4E) → 0x08 until Phase 4. Other services → 0x08; instance ≠ 1 → 0x05.
  - `Object.TcpIpInterface` (class 0xF5), Get_Attribute_Single from `config.network` (defaults in parens): 1 status `<<1::32-little>>` · 2 capability `<<0::32-little>>` · 3 control `<<0::32-little>>` · 4 physical link `<<2::16-little, 0x20, 0xF6, 0x24, 0x01>>` · 5 interface config: ip+mask+gateway (each an IP tuple, default `{0,0,0,0}`) + two zero name servers + domain STRING (`<<len::16-little, chars>>`, default "") · 6 hostname STRING (default "") · 8 mcast TTL `<<1>>` · 13 `<<div(inactivity_timeout, 1000)::16-little>>`. **IP encoding choice:** UDINT little-endian of the network-order integer — `{a,b,c,d}` encodes as `<<d, c, b, a>>`; the pycomm3 interop run (Task 8) must confirm this reads correctly and the report must note the observed bytes.
  - `Object.EthernetLink` (class 0xF6): 1 speed `<<100::32-little>>` (opt `:speed`) · 2 flags `<<3::32-little>>` (link up + full duplex) · 3 MAC 6 bytes (opt `:mac`, default `<<0,0,0,0,0,0>>`).
  - Both: unknown attr → 0x14, instance ≠ 1 → 0x05, other services → 0x08.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/object/network_objects_test.exs`:

```elixir
defmodule Eipex.Adapter.Object.NetworkObjectsTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{Config, MessageRouter}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.Identity

  defp config do
    %Config{
      identity: %Identity{vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
                          revision: {1, 0}, serial_number: 1, product_name: "X"},
      handler: Eipex.Adapter.Handler.Default,
      inactivity_timeout: 120_000,
      network: %{ip: {192, 168, 1, 10}, netmask: {255, 255, 255, 0},
                 gateway: {192, 168, 1, 1}, hostname: "eipex",
                 mac: <<1, 2, 3, 4, 5, 6>>},
      objects: %{0x01 => Eipex.Adapter.Object.Identity,
                 0x06 => Eipex.Adapter.Object.ConnectionManager,
                 0xF5 => Eipex.Adapter.Object.TcpIpInterface,
                 0xF6 => Eipex.Adapter.Object.EthernetLink}
    }
  end

  defp roundtrip(config, service, path, data \\ <<>>) do
    request = MR.encode_request(service, path, data)
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "unconnected send unwraps, dispatches locally and replies with the embedded response" do
    embedded = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    request = CM.encode_unconnected_send(embedded, [{:port, 1, 0}], [])

    {:ok, response} = config() |> MessageRouter.dispatch(request) |> MR.decode_response()

    # the reply is the embedded Get_Attribute_Single response, not a 0x52 wrapper
    assert %{service: 0x0E, status_name: :success, data: <<0x4D, 0x00>>} = response
  end

  test "malformed unconnected send payload maps to not_enough_data" do
    assert %{status_name: :not_enough_data} =
             roundtrip(config(), 0x52, [class: 0x06, instance: 1], <<1, 2, 3>>)
  end

  test "forward open family answers service_not_supported until phase 4" do
    for service <- [0x54, 0x5B, 0x4E] do
      assert %{status_name: :service_not_supported} =
               roundtrip(config(), service, [class: 0x06, instance: 1], <<0>>)
    end
  end

  test "tcp/ip interface attributes" do
    cfg = config()

    assert %{data: <<1::32-little>>} =
             roundtrip(cfg, 0x0E, class: 0xF5, instance: 1, attribute: 1)

    assert %{data: <<2::16-little, 0x20, 0xF6, 0x24, 0x01>>} =
             roundtrip(cfg, 0x0E, class: 0xF5, instance: 1, attribute: 4)

    # ip 192.168.1.10 as UDINT little-endian of the network-order integer
    assert %{data: <<10, 1, 168, 192, 0, 255, 255, 255, 1, 1, 168, 192,
                     0::32, 0::32, 0::16>>} =
             roundtrip(cfg, 0x0E, class: 0xF5, instance: 1, attribute: 5)

    assert %{data: <<5::16-little, "eipex">>} =
             roundtrip(cfg, 0x0E, class: 0xF5, instance: 1, attribute: 6)

    assert %{data: <<120::16-little>>} =
             roundtrip(cfg, 0x0E, class: 0xF5, instance: 1, attribute: 13)
  end

  test "ethernet link attributes" do
    cfg = config()

    assert %{data: <<100::32-little>>} =
             roundtrip(cfg, 0x0E, class: 0xF6, instance: 1, attribute: 1)

    assert %{data: <<1, 2, 3, 4, 5, 6>>} =
             roundtrip(cfg, 0x0E, class: 0xF6, instance: 1, attribute: 3)
  end

  test "unknown attributes and instances on network objects" do
    cfg = config()

    assert %{status_name: :attribute_not_supported} =
             roundtrip(cfg, 0x0E, class: 0xF5, instance: 1, attribute: 99)

    assert %{status_name: :path_destination_unknown} =
             roundtrip(cfg, 0x0E, class: 0xF6, instance: 2, attribute: 1)
  end
end
```

Netmask note for the attr-5 vector: `{255,255,255,0}` network-order integer is
`0xFFFFFF00`; little-endian bytes are `<<0x00, 0xFF, 0xFF, 0xFF>>` — matching
`<<0, 255, 255, 255>>` in the assertion.

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/object/network_objects_test.exs`
Expected: FAIL — modules undefined.

- [ ] **Step 3: Implement the three objects**

`lib/eipex/adapter/object/connection_manager.ex`:

```elixir
defmodule Eipex.Adapter.Object.ConnectionManager do
  @moduledoc """
  Connection Manager object (class 0x06), UCMM subset: Unconnected Send is
  unwrapped and dispatched locally (single-hop routes are accepted — this
  device is the target). Forward Open/Close arrive in Phase 4.
  """

  @behaviour Eipex.Adapter.Object

  alias Eipex.CIP.ConnectionManager, as: CM

  @unconnected_send 0x52
  @forward_close 0x4E
  @forward_open 0x54
  @large_forward_open 0x5B

  @impl true
  def handle_service(@unconnected_send, 1, [], data, ctx) do
    case CM.decode_unconnected_send(data) do
      {:ok, %{embedded: embedded}} ->
        {:raw, Eipex.Adapter.MessageRouter.dispatch(ctx.config, embedded)}

      {:error, _} ->
        {:error, 0x13, []}
    end
  end

  def handle_service(service, 1, _path, _data, _ctx)
      when service in [@forward_open, @large_forward_open, @forward_close] do
    {:error, 0x08, []}
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}
end
```

`lib/eipex/adapter/object/tcp_ip_interface.ex`:

```elixir
defmodule Eipex.Adapter.Object.TcpIpInterface do
  @moduledoc """
  TCP/IP Interface object (class 0xF5). Attribute values come from the
  adapter's `network` options. IPs encode as UDINT little-endian of the
  network-order integer (`{a,b,c,d}` -> `<<d, c, b, a>>`).
  """

  @behaviour Eipex.Adapter.Object

  @get_attribute_single 0x0E

  @impl true
  def handle_service(@get_attribute_single, 1, [{:attribute, n}], <<>>, ctx) do
    case attribute(n, ctx.config) do
      nil -> {:error, 0x14, []}
      data -> {:reply, data}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp attribute(1, _config), do: <<1::32-little>>
  defp attribute(2, _config), do: <<0::32-little>>
  defp attribute(3, _config), do: <<0::32-little>>
  defp attribute(4, _config), do: <<2::16-little, 0x20, 0xF6, 0x24, 0x01>>

  defp attribute(5, config) do
    net = config.network

    encode_ip(Map.get(net, :ip, {0, 0, 0, 0})) <>
      encode_ip(Map.get(net, :netmask, {0, 0, 0, 0})) <>
      encode_ip(Map.get(net, :gateway, {0, 0, 0, 0})) <>
      <<0::32, 0::32>> <>
      encode_string(Map.get(net, :domain, ""))
  end

  defp attribute(6, config), do: encode_string(Map.get(config.network, :hostname, ""))
  defp attribute(8, _config), do: <<1>>
  defp attribute(13, config), do: <<div(config.inactivity_timeout, 1000)::16-little>>
  defp attribute(_, _config), do: nil

  defp encode_ip({a, b, c, d}), do: <<d, c, b, a>>
  defp encode_string(s), do: <<byte_size(s)::16-little, s::binary>>
end
```

`lib/eipex/adapter/object/ethernet_link.ex`:

```elixir
defmodule Eipex.Adapter.Object.EthernetLink do
  @moduledoc "Ethernet Link object (class 0xF6): speed, flags and MAC."

  @behaviour Eipex.Adapter.Object

  @get_attribute_single 0x0E

  @impl true
  def handle_service(@get_attribute_single, 1, [{:attribute, n}], <<>>, ctx) do
    case attribute(n, ctx.config.network) do
      nil -> {:error, 0x14, []}
      data -> {:reply, data}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp attribute(1, net), do: <<Map.get(net, :speed, 100)::32-little>>
  defp attribute(2, _net), do: <<3::32-little>>
  defp attribute(3, net), do: Map.get(net, :mac, <<0, 0, 0, 0, 0, 0>>)
  defp attribute(_, _net), do: nil
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/object/network_objects_test.exs`
Expected: PASS, 6 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Connection Manager (Unconnected Send), TCP/IP Interface and Ethernet Link objects`

```bash
mix format && git add -A && git commit -m "feat: adapter network objects and unconnected send"
```

---

### Task 6: Listener + SessionHandler + loopback scanner tests

**Files:**
- Create: `lib/eipex/adapter/listener.ex`, `lib/eipex/adapter/session_handler.ex`
- Modify: `lib/eipex/adapter/adapter.ex` (start the listener in init; wire `port/1`)
- Test: `test/eipex/adapter/session_handler_test.exs`, `test/eipex/adapter/loopback_test.exs`

**Interfaces:**
- Consumes: everything above; `Eipex.Scanner` (Phase 2) as loopback client.
- Produces:
  - `Eipex.Adapter.Listener.start_link(%{port, ip, sessions_sup, config})`, `Listener.port/1 :: {:ok, port}`. Acceptor loop: accept → `DynamicSupervisor.start_child` (`SessionHandler`, `restart: :temporary`) → `controlling_process` → `SessionHandler.activate/1` (activation AFTER handoff avoids the message-to-acceptor race).
  - `Eipex.Adapter.SessionHandler`: per-connection GenServer. Frame handling: RegisterSession (assign nonzero unique handle; second register → status 0x0001) · UnRegisterSession (close + stop) · SendRRData (session handle mismatch → status 0x0064; malformed CPF → 0x0003; else dispatch and reply with the same sender context) · NOP (ignore) · ListIdentity over TCP (identity CPF) · ListServices (item 0x0100, capability 0x0020 = TCP CIP, name "Communications\0\0") · anything else, including `{:unknown, code}` and `:send_unit_data` → echo with status 0x0001. Inactivity timeout (config) closes with `{:shutdown, :inactivity_timeout}`.
  - `Eipex.Adapter.port/1` now returns the bound port.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/session_handler_test.exs` — raw gen_tcp client speaking real bytes:

```elixir
defmodule Eipex.Adapter.SessionHandlerTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap}

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
    %Encap{command: :register_session, status: 0, session_handle: handle} = recv_frame(socket)
    assert handle != 0
    handle
  end

  test "registers a session and answers identity over UCMM" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)

    mr = Eipex.CIP.MessageRouter.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}])
    send_frame(socket, %Encap{Encap.send_rr_data(handle, cpf) | sender_context: <<7::64>>})

    reply = recv_frame(socket)
    assert %Encap{command: :send_rr_data, status: 0, sender_context: <<7::64>>} = reply
    {:ok, items} = reply |> Encap.unwrap_cpf() |> then(fn {:ok, c} -> CPF.decode(c) end)
    [{:unconnected_data, response}] = for {:unconnected_data, _} = i <- items, do: i

    assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
             Eipex.CIP.MessageRouter.decode_response(response)
  end

  test "second register on the same connection is rejected" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)

    send_frame(socket, Encap.register_session())
    assert %Encap{command: :register_session, status: 0x0001} = recv_frame(socket)
  end

  test "send_rr_data with a wrong session handle answers 0x64" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)

    send_frame(socket, Encap.send_rr_data(0xDEAD, <<>>))
    assert %Encap{command: :send_rr_data, status: 0x0064} = recv_frame(socket)
  end

  test "malformed CPF answers 0x0003" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)

    send_frame(socket, Encap.send_rr_data(handle, <<0xFF>>))
    assert %Encap{command: :send_rr_data, status: 0x0003} = recv_frame(socket)
  end

  test "unknown commands echo with status 0x0001" do
    {_pid, port} = start_adapter()
    socket = connect(port)

    send_frame(socket, %Encap{command: {:unknown, 0xAB}, sender_context: <<1::64>>})

    assert %Encap{command: {:unknown, 0xAB}, status: 0x0001, sender_context: <<1::64>>} =
             recv_frame(socket)
  end

  test "list_identity and list_services answer over TCP without a session" do
    {_pid, port} = start_adapter()
    socket = connect(port)

    send_frame(socket, Encap.list_identity())
    reply = recv_frame(socket)
    {:ok, [{:identity, id}]} = CPF.decode(reply.data)
    assert id.product_name == "Eipex Adapter"

    send_frame(socket, %Encap{command: :list_services})

    assert %Encap{command: :list_services,
                  data: <<1::16-little, 0x0100::16-little, 20::16-little, 1::16-little,
                          0x0020::16-little, "Communications", 0, 0>>} = recv_frame(socket)
  end

  test "inactivity timeout closes the connection" do
    {_pid, port} = start_adapter(inactivity_timeout: 100)
    socket = connect(port)
    _handle = register(socket)

    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
  end

  test "a crashed session handler does not kill the listener" do
    {pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)
    :gen_tcp.close(socket)

    Process.sleep(50)
    socket2 = connect(port)
    assert register(socket2) != 0
    assert Process.alive?(pid)
  end
end
```

`test/eipex/adapter/loopback_test.exs` — the flagship: our scanner against our adapter:

```elixir
defmodule Eipex.Adapter.LoopbackTest do
  use ExUnit.Case

  alias Eipex.Scanner

  defmodule ConfigGuard do
    use Eipex.Adapter.Handler
    def after_assembly_write(151, <<0xA5, _>>, _ctx), do: :ok
    def after_assembly_write(151, _, _ctx), do: {:error, 0x09}
    def after_assembly_write(_, _, _), do: :ok
  end

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  defp start_pair(extra \\ []) do
    {:ok, adapter} =
      Eipex.Adapter.start_link(
        [identity: @identity, handler: ConfigGuard,
         assemblies: [input: [instance: 100, size: 4],
                      output: [instance: 150, size: 4],
                      config: [instance: 151, size: 2]],
         port: 0] ++ extra
      )

    {:ok, port} = Eipex.Adapter.port(adapter)
    {:ok, scanner} = Scanner.start_link(host: {127, 0, 0, 1}, port: port)
    {adapter, scanner}
  end

  test "scanner reads identity attributes from our adapter" do
    {_adapter, scanner} = start_pair()

    assert {:ok, <<0x4D, 0x00>>} = Scanner.get_attribute(scanner, 0x01, 1, 1)
    assert {:ok, all} = Scanner.get_attributes_all(scanner, 0x01, 1)
    assert <<0x4D::16-little, _::binary>> = all

    Scanner.close(scanner)
  end

  test "scanner writes and reads assemblies end to end" do
    {adapter, scanner} = start_pair()

    assert :ok = Scanner.set_attribute(scanner, 0x04, 150, 3, <<1, 2, 3, 4>>)
    assert {:ok, <<1, 2, 3, 4>>} = Scanner.get_attribute(scanner, 0x04, 150, 3)
    assert {:ok, <<1, 2, 3, 4>>} = Eipex.Adapter.read_assembly(adapter, 150)

    assert {:error, {:cip, :invalid_attribute_value, _}} =
             Scanner.set_attribute(scanner, 0x04, 151, 3, <<0xFF, 0x00>>)

    Scanner.close(scanner)
  end

  test "routed requests traverse the adapter's connection manager" do
    {_adapter, scanner} = start_pair()

    assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
             Scanner.generic_message(scanner,
               service: 0x0E, class: 0x01, instance: 1, attribute: 1,
               route_path: [backplane: 0])

    Scanner.close(scanner)
  end

  test "CIP errors surface through the scanner helpers" do
    {_adapter, scanner} = start_pair()

    assert {:error, {:cip, :path_destination_unknown, _}} =
             Scanner.get_attribute(scanner, 0x77, 1, 1)

    Scanner.close(scanner)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/session_handler_test.exs test/eipex/adapter/loopback_test.exs`
Expected: FAIL — `Listener`/`SessionHandler` undefined, `Adapter.port/1` returns `{:error, :not_listening}`.

- [ ] **Step 3: Implement Listener, SessionHandler, and wire the adapter**

`lib/eipex/adapter/listener.ex`:

```elixir
defmodule Eipex.Adapter.Listener do
  @moduledoc """
  TCP acceptor for the adapter: accepts on the configured port and hands
  each connection to a fresh SessionHandler under the sessions supervisor.
  Activation happens after `controlling_process/2` so no TCP message can
  race to the acceptor.
  """

  use GenServer

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def port(listener), do: GenServer.call(listener, :port)

  @impl true
  def init(%{port: port, ip: ip, sessions_sup: sessions_sup, config: config}) do
    listen_opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip]

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, listen} ->
        acceptor = spawn_link(fn -> accept_loop(listen, sessions_sup, config) end)
        {:ok, %{listen: listen, acceptor: acceptor}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, :inet.port(state.listen), state}

  defp accept_loop(listen, sessions_sup, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        {:ok, pid} =
          DynamicSupervisor.start_child(
            sessions_sup,
            {Eipex.Adapter.SessionHandler, {socket, config}}
          )

        :ok = :gen_tcp.controlling_process(socket, pid)
        Eipex.Adapter.SessionHandler.activate(pid)
        accept_loop(listen, sessions_sup, config)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        accept_loop(listen, sessions_sup, config)
    end
  end
end
```

`lib/eipex/adapter/session_handler.ex`:

```elixir
defmodule Eipex.Adapter.SessionHandler do
  @moduledoc """
  One process per TCP connection: encapsulation framing, session handle
  lifecycle, and UCMM dispatch. Dies quietly on disconnect
  (`restart: :temporary`) without touching the listener.
  """

  use GenServer, restart: :temporary

  alias Eipex.{CPF, Encap}
  alias Eipex.Adapter.MessageRouter

  def start_link({socket, config}), do: GenServer.start_link(__MODULE__, {socket, config})

  def activate(pid), do: GenServer.cast(pid, :activate)

  @impl true
  def init({socket, config}) do
    {:ok, %{socket: socket, config: config, buffer: <<>>, session_handle: nil, timer: nil}}
  end

  @impl true
  def handle_cast(:activate, state) do
    :ok = :inet.setopts(state.socket, active: :once)
    {:noreply, arm_inactivity(state)}
  end

  @impl true
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    state = drain(%{state | buffer: state.buffer <> data})
    :ok = :inet.setopts(socket, active: :once)
    {:noreply, arm_inactivity(state)}
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state), do: {:stop, :normal, state}
  def handle_info({:tcp_error, socket, _}, %{socket: socket} = state), do: {:stop, :normal, state}

  def handle_info(:inactivity_timeout, state) do
    :gen_tcp.close(state.socket)
    {:stop, {:shutdown, :inactivity_timeout}, state}
  end

  def handle_info(:stop_normal, state), do: {:stop, :normal, state}

  # -- Frame handling ------------------------------------------------------------

  defp drain(state) do
    case Encap.decode(state.buffer) do
      {:ok, frame, rest} -> %{state | buffer: rest} |> handle_frame(frame) |> drain()
      :partial -> state
    end
  end

  defp handle_frame(state, %Encap{command: :register_session} = frame) do
    if state.session_handle do
      reply(state, %Encap{frame | status: 0x0001})
      state
    else
      handle = :erlang.unique_integer([:positive]) |> rem(0xFFFF_FFFE) |> Kernel.+(1)
      reply(state, %Encap{frame | session_handle: handle})
      %{state | session_handle: handle}
    end
  end

  defp handle_frame(state, %Encap{command: :unregister_session}) do
    :gen_tcp.close(state.socket)
    # finish draining this packet, then stop; no reply is defined for unregister
    send(self(), :stop_normal)
    state
  end

  defp handle_frame(state, %Encap{command: :send_rr_data, session_handle: handle} = frame) do
    cond do
      is_nil(state.session_handle) or handle != state.session_handle ->
        reply(state, %Encap{frame | status: 0x0064, data: <<>>})

      true ->
        case rr_payload(frame) do
          {:ok, mr_request} ->
            response = MessageRouter.dispatch(state.config, mr_request)
            cpf = CPF.encode([:null_address, {:unconnected_data, response}])

            reply(state, %Encap{
              Encap.send_rr_data(state.session_handle, cpf)
              | sender_context: frame.sender_context
            })

          {:error, _} ->
            reply(state, %Encap{frame | status: 0x0003, data: <<>>})
        end
    end

    state
  end

  defp handle_frame(state, %Encap{command: :nop}), do: state

  defp handle_frame(state, %Encap{command: :list_identity} = frame) do
    reply(state, %Encap{frame | data: CPF.encode([{:identity, state.config.identity}])})
    state
  end

  defp handle_frame(state, %Encap{command: :list_services} = frame) do
    item =
      <<1::16-little, 0x0100::16-little, 20::16-little, 1::16-little, 0x0020::16-little,
        "Communications", 0, 0>>

    reply(state, %Encap{frame | data: item})
    state
  end

  # send_unit_data (phase 4) and unknown commands: invalid command
  defp handle_frame(state, %Encap{} = frame) do
    reply(state, %Encap{frame | status: 0x0001, data: <<>>})
    state
  end

  defp rr_payload(frame) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [mr | _] <- for({:unconnected_data, d} <- items, do: d) do
      {:ok, mr}
    else
      _ -> {:error, :malformed}
    end
  end

  defp reply(state, frame), do: :gen_tcp.send(state.socket, Encap.encode(frame))

  defp arm_inactivity(state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    timer = Process.send_after(self(), :inactivity_timeout, state.config.inactivity_timeout)
    %{state | timer: timer}
  end
end
```

In `lib/eipex/adapter/adapter.ex` `init/1`, replace the listener placeholder:

```elixir
      {:ok, listener} =
        Eipex.Adapter.Listener.start_link(%{
          port: Keyword.get(opts, :port, 44_818),
          ip: Keyword.get(opts, :ip, {0, 0, 0, 0}),
          sessions_sup: sessions_sup,
          config: config
        })

      {:ok, %{config: config, sessions_sup: sessions_sup, listener: listener, opts: opts}}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/session_handler_test.exs test/eipex/adapter/loopback_test.exs`
Expected: PASS, 12 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Adapter TCP listener and session handler; loopback tests against our scanner`

```bash
mix format && git add -A && git commit -m "feat: adapter listener and session handler"
```

---

### Task 7: UDP ListIdentity discovery responder

**Files:**
- Create: `lib/eipex/adapter/discovery.ex`
- Modify: `lib/eipex/adapter/adapter.ex` (start it when `discovery:` opts given; expose `discovery_port/1`)
- Test: `test/eipex/adapter/discovery_test.exs`

**Interfaces:**
- Consumes: `Encap`, `CPF`, `config.identity`; `Eipex.Scanner.discover/1` (Phase 2) as the test client.
- Produces:
  - `Eipex.Adapter.Discovery.start_link(%{port, delay: {min_ms, max_ms}, config})` — binds UDP (reuseaddr), answers ListIdentity datagrams with the identity item after a uniform random delay in `[min_ms, max_ms]` (ODVA anti-storm behavior; `{0, 0}` in tests). Ignores anything else. `Discovery.port/1` for tests.
  - Adapter opts: `discovery: false` (default) | keyword `[port: 44_818, delay: {0, 500}]`. `Eipex.Adapter.discovery_port(adapter) :: {:ok, port} | {:error, :not_running}`.

- [ ] **Step 1: Write the failing tests**

`test/eipex/adapter/discovery_test.exs`:

```elixir
defmodule Eipex.Adapter.DiscoveryTest do
  use ExUnit.Case

  @identity [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
             revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"]

  defp start_adapter(discovery) do
    {:ok, pid} =
      Eipex.Adapter.start_link(
        identity: @identity, assemblies: [], port: 0, discovery: discovery
      )

    pid
  end

  test "answers our scanner's unicast discover" do
    adapter = start_adapter(port: 0, delay: {0, 0})
    {:ok, udp_port} = Eipex.Adapter.discovery_port(adapter)

    assert {:ok, [%Eipex.Identity{product_name: "Eipex Adapter", vendor_id: 0x4D}]} =
             Eipex.Scanner.discover(address: {127, 0, 0, 1}, port: udp_port, timeout: 500)
  end

  test "ignores non-ListIdentity datagrams" do
    adapter = start_adapter(port: 0, delay: {0, 0})
    {:ok, udp_port} = Eipex.Adapter.discovery_port(adapter)

    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, udp_port, <<0xDE, 0xAD>>)
    assert {:error, :timeout} = :gen_udp.recv(socket, 0, 200)
    :gen_udp.close(socket)
  end

  test "discovery disabled by default" do
    adapter = start_adapter(false)
    assert {:error, :not_running} = Eipex.Adapter.discovery_port(adapter)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/adapter/discovery_test.exs`
Expected: FAIL — `Discovery` undefined / `discovery_port/1` undefined.

- [ ] **Step 3: Implement**

`lib/eipex/adapter/discovery.ex`:

```elixir
defmodule Eipex.Adapter.Discovery do
  @moduledoc """
  UDP ListIdentity responder (port 44818). Replies are delayed by a uniform
  random interval to avoid response storms on broadcast discovery
  (ODVA-recommended behavior).
  """

  use GenServer

  alias Eipex.{CPF, Encap}

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def port(server), do: GenServer.call(server, :port)

  @impl true
  def init(%{port: port, delay: delay, config: config}) do
    case :gen_udp.open(port, [:binary, active: true, reuseaddr: true]) do
      {:ok, socket} -> {:ok, %{socket: socket, delay: delay, config: config}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, :inet.port(state.socket), state}

  @impl true
  def handle_info({:udp, socket, ip, port, data}, %{socket: socket} = state) do
    case Encap.decode(data) do
      {:ok, %Encap{command: :list_identity} = frame, _rest} ->
        Process.send_after(self(), {:respond, ip, port, frame}, random_delay(state.delay))

      _ ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info({:respond, ip, port, frame}, state) do
    reply = %Encap{frame | data: CPF.encode([{:identity, state.config.identity}])}
    _ = :gen_udp.send(state.socket, ip, port, Encap.encode(reply))
    {:noreply, state}
  end

  defp random_delay({min, max}) when max > min, do: min + :rand.uniform(max - min + 1) - 1
  defp random_delay({min, _}), do: min
end
```

In `Eipex.Adapter`: start it in `init/1` when configured, add the API:

```elixir
      discovery =
        case Keyword.get(opts, :discovery, false) do
          false ->
            nil

          disc_opts ->
            {:ok, pid} =
              Eipex.Adapter.Discovery.start_link(%{
                port: Keyword.get(disc_opts, :port, 44_818),
                delay: Keyword.get(disc_opts, :delay, {0, 500}),
                config: config
              })

            pid
        end
```

(store `discovery: discovery` in state) and:

```elixir
  @spec discovery_port(GenServer.server()) ::
          {:ok, :inet.port_number()} | {:error, :not_running}
  def discovery_port(server), do: GenServer.call(server, :discovery_port)

  def handle_call(:discovery_port, _from, state) do
    case state.discovery do
      nil -> {:reply, {:error, :not_running}, state}
      pid -> {:reply, Eipex.Adapter.Discovery.port(pid), state}
    end
  end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/adapter/discovery_test.exs`
Expected: PASS, 3 tests, 0 failures. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] UDP ListIdentity discovery responder with anti-storm delay`

```bash
mix format && git add -A && git commit -m "feat: adapter discovery responder"
```

---

### Task 8: pycomm3 interop harness

**Files:**
- Create: `interop/pycomm3/check_adapter.py`
- Create: `test/interop/pycomm3_test.exs`
- Modify: `README.md` (extend the interop section)

**Interfaces:**
- Consumes: the full adapter; Docker (`--network host`, available on this machine — verified in Phase 2).
- Produces: `mix test --include interop` also validates the adapter against pycomm3, the reference Python scanner. Real run MANDATORY.

- [ ] **Step 1: Write the python check script**

`interop/pycomm3/check_adapter.py`:

```python
"""Exercises an Eipex adapter with pycomm3 (reference scanner). Prints JSON."""

import json
import os

from pycomm3 import CIPDriver, Services

HOST = os.environ.get("ADAPTER_HOST", "127.0.0.1")
PORT = int(os.environ.get("ADAPTER_PORT", "44821"))

results = {}
driver = CIPDriver(f"{HOST}:{PORT}")
driver.open()

vendor = driver.generic_message(
    service=Services.get_attribute_single, class_code=1, instance=1,
    attribute=1, connected=False, name="vendor")
results["vendor"] = list(vendor.value) if vendor.value else None
results["vendor_ok"] = vendor.error is None

write = driver.generic_message(
    service=Services.set_attribute_single, class_code=4, instance=150,
    attribute=3, request_data=b"\xaa\xbb\xcc\xdd", connected=False, name="write")
results["write_ok"] = write.error is None

read = driver.generic_message(
    service=Services.get_attribute_single, class_code=4, instance=150,
    attribute=3, connected=False, name="read")
results["readback_ok"] = bytes(read.value) == b"\xaa\xbb\xcc\xdd" if read.value else False

bad = driver.generic_message(
    service=Services.get_attribute_single, class_code=0x77, instance=1,
    attribute=1, connected=False, name="unknown_class")
results["unknown_class_errors"] = bad.error is not None

driver.close()
print(json.dumps(results))
```

- [ ] **Step 2: Write the interop test**

`test/interop/pycomm3_test.exs`:

```elixir
defmodule Eipex.Interop.Pycomm3Test do
  @moduledoc """
  Interop: pycomm3 (reference Python scanner) against our adapter.
  Requires docker. Run with: mix test --include interop
  """

  use ExUnit.Case

  @moduletag :interop
  @moduletag timeout: 300_000

  test "pycomm3 talks to our adapter over UCMM" do
    {:ok, _adapter} =
      Eipex.Adapter.start_link(
        identity: [vendor_id: 0x4D, device_type: 0x0C, product_code: 0x77,
                   revision: {1, 2}, serial_number: 0x99, product_name: "Eipex Adapter"],
        assemblies: [output: [instance: 150, size: 4]],
        port: 44_821,
        ip: {0, 0, 0, 0}
      )

    script = Path.expand("../../interop/pycomm3/check_adapter.py", __DIR__)

    {output, exit_code} =
      System.cmd(
        "docker",
        ["run", "--rm", "--network", "host",
         "-v", "#{script}:/check_adapter.py:ro",
         "-e", "ADAPTER_HOST=127.0.0.1", "-e", "ADAPTER_PORT=44821",
         "python:3.11-slim", "sh", "-c",
         "pip install --quiet pycomm3 && python /check_adapter.py"],
        stderr_to_stdout: true
      )

    assert exit_code == 0, "pycomm3 run failed:\n#{output}"

    json = output |> String.split("\n", trim: true) |> List.last()
    results = JSON.decode!(json)

    assert results["vendor_ok"]
    assert results["vendor"] == [0x4D, 0x00]
    assert results["write_ok"]
    assert results["readback_ok"]
    assert results["unknown_class_errors"]
  end
end
```

(`JSON` is the Elixir 1.18 stdlib module — no dependency. If running on an
older Elixir, decode the five booleans with `String.contains?/2` instead.)

- [ ] **Step 3: Run it for real**

```bash
mix test --include interop test/interop/pycomm3_test.exs
```

Expected: 1 test, 0 failures (first run pulls the image + pip install, allow a
few minutes). If pycomm3's `generic_message` shapes differ from the script's
expectations (e.g. `.value` vs raw bytes), adjust the SCRIPT to observed
reality — keep the five result keys and their meaning; document exactly what
pycomm3 returned in your report. If pycomm3 rejects the `host:port` path
syntax, run the adapter on port 44818 instead (drop the custom port from test
and script) and note it. Confirm hermetic `mix test` still excludes the test.

- [ ] **Step 4: Document**

In `README.md`'s interop section, add:

```markdown
The adapter side is exercised with pycomm3:

    mix test --include interop test/interop/pycomm3_test.exs
```

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] pycomm3 interop harness for the adapter`

```bash
mix format && git add -A && git commit -m "test: pycomm3 adapter interop"
```

---

### Task 9: Scanner deferred hardening (from the Phase 2 final review)

**Files:**
- Modify: `lib/eipex/scanner.ex`
- Modify: `test/support/scripted_target.ex` (two small opts)
- Test: `test/eipex/scanner_test.exs` (append)

**Interfaces:**
- Consumes: existing scanner internals; `CM.decode_unconnected_send/1` (Task 1) for the tick test.
- Produces (closing three deferred findings):
  1. `register_session/2` returns leftover bytes and `init/1` seeds `state.buffer` with them (no frame loss on pipelining targets).
  2. `handle_call({:request, ...})` rescues builder exceptions → `{:reply, {:error, {:invalid_request, message}}, state}` — one caller's bad input no longer kills the session.
  3. Routed requests derive `timeout_ticks` from the request timeout with the spec's 10 s floor: `ticks = min(255, ceil(max(timeout, 10_000) / 1024))` (priority_time_tick stays 0x0A = 1024 ms tick).
- ScriptedTarget additions: `register_trailer: binary` (bytes appended to the RegisterSession reply packet) and `reply_prefix: binary` (bytes sent immediately before the first SendRRData reply).

- [ ] **Step 1: Write the failing tests (append to `test/eipex/scanner_test.exs`)**

```elixir
  describe "deferred hardening" do
    test "bytes pipelined after RegisterSession are not lost" do
      # target sends: register reply + FIRST HALF of a NOP frame in one packet;
      # then, before the first request's reply, the SECOND HALF of that NOP.
      nop = Encap.encode(Encap.nop())
      half = div(byte_size(nop), 2)
      <<nop_a::binary-size(half), nop_b::binary>> = nop

      target =
        ScriptedTarget.start(get_attr_handler(<<1>>),
          register_trailer: nop_a,
          reply_prefix: nop_b
        )

      pid = start_scanner(target)

      # pre-fix: nop_a is discarded, so nop_b + reply misalign and this times out
      assert {:ok, %{data: <<1>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 500)

      Scanner.close(pid)
    end

    test "an invalid request errors without killing the session" do
      target = ScriptedTarget.start(get_attr_handler(<<2>>))
      pid = start_scanner(target)

      long = String.duplicate("a", 300)
      assert {:error, {:invalid_request, _}} = Scanner.generic_message(pid, service: 0x4C, symbolic: long)

      # session survives and still works
      assert {:ok, %{data: <<2>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1)

      Scanner.close(pid)
    end

    test "routed requests derive timeout ticks from the request timeout" do
      test_pid = self()

      handler = fn mr ->
        {:ok, %{service: 0x52, data: data}} = MessageRouter.decode_request(mr)
        {:ok, decoded} = Eipex.CIP.ConnectionManager.decode_unconnected_send(data)
        send(test_pid, {:ticks, decoded.timeout_ticks})
        MessageRouter.encode_response(0x0E, 0x00, data: <<1>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target, route_path: [backplane: 0])

      {:ok, _} =
        Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 30_000)

      assert_receive {:ticks, 30}

      {:ok, _} = Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1)
      # default 5s request timeout -> 10s spec floor -> ceil(10_000/1024) = 10
      assert_receive {:ticks, 10}

      Scanner.close(pid)
    end
  end
```

ScriptedTarget changes (exact): the Agent state gains `prefix_sent: false`;
`drain/5` passes `agent` into `handle_frame` (arity becomes 5) and into
`send_reply`. The two touched clauses become:

```elixir
  defp handle_frame(socket, %Encap{command: :register_session} = frame, _handler, _agent, opts) do
    reply = %Encap{frame | session_handle: @session_handle}
    :gen_tcp.send(socket, Encap.encode(reply) <> (opts[:register_trailer] || <<>>))
  end

  defp send_reply(socket, binary, opts, agent) do
    case opts[:reply_prefix] do
      nil ->
        :ok

      prefix ->
        already_sent =
          Agent.get_and_update(agent, fn s -> {s.prefix_sent, %{s | prefix_sent: true}} end)

        unless already_sent do
          :gen_tcp.send(socket, prefix)
          Process.sleep(5)
        end
    end

    # existing split_replies/plain send logic unchanged below
    ...
  end
```

(All other `handle_frame` clauses just gain the extra `_agent` argument.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/scanner_test.exs`
Expected: the pipelining test FAILS with `{:error, :timeout}`; the invalid-request test FAILS (session process crashes); the ticks test FAILS (`assert_receive {:ticks, 30}` receives `{:ticks, 5}` — the Phase 1 default).

- [ ] **Step 3: Implement**

In `lib/eipex/scanner.ex`:

a) `register_session/2` returns `{:ok, handle, rest}` — `recv_frame` already has the rest, thread it:

```elixir
  defp register_session(socket, timeout) do
    with :ok <- :gen_tcp.send(socket, Encap.encode(Encap.register_session())),
         {:ok, %Encap{command: :register_session, status: 0, session_handle: handle}, rest} <-
           recv_frame(socket, <<>>, timeout) do
      {:ok, handle, rest}
    else
      {:ok, %Encap{command: command, status: 0}, _rest} -> {:error, {:unexpected_reply, command}}
      {:ok, %Encap{status: status}, _rest} -> {:error, {:encap, Encap.status_name(status)}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp recv_frame(socket, buffer, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        case Encap.decode(buffer <> data) do
          {:ok, frame, rest} -> {:ok, frame, rest}
          :partial -> recv_frame(socket, buffer <> data, timeout)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
```

and in `init/1`: `{:ok, handle, rest} <- register_session(socket, timeout)` then
`buffer: rest` in the initial `%State{}`.

b) rescue in the request path:

```elixir
  def handle_call({:request, opts}, from, state) do
    case build_request(opts, state) do
      {:ok, mr} -> ...unchanged...
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  rescue
    exception ->
      {:reply, {:error, {:invalid_request, Exception.message(exception)}}, state}
  end
```

c) tick derivation — in `build_request/2`'s route branch:

```elixir
      case request_route(opts, state) do
        :none ->
          {:ok, mr}

        route ->
          timeout = Keyword.get(opts, :timeout, state.timeout)
          ticks = min(255, ceil(max(timeout, 10_000) / 1024))
          {:ok, ConnectionManager.encode_unconnected_send(mr, route, timeout_ticks: ticks)}
      end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/scanner_test.exs`
Expected: PASS. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Fixed] Scanner: pipelined-byte buffering, invalid-request isolation, derived timeout ticks`

```bash
mix format && git add -A && git commit -m "fix: scanner deferred hardening"
```

---

## Completion criteria for Phase 3

- `mix test` green and hermetic; all Phase 1+2 tests untouched.
- Loopback tests (our scanner ↔ our adapter) green, including routed requests.
- `mix test --include interop` green for BOTH cpppo (scanner side) and pycomm3 (adapter side), run for real at least once with output in the task report.
- `mix format --check-formatted` passes; zero runtime deps.
- One CHANGELOG line per task.

## After this plan

Phase 4 (connected class 3 messaging: Forward Open/Close in both roles +
SendUnitData) builds on: the adapter's `Object.ConnectionManager` (replace the
0x08 answers), a `SessionHandler` clause for `:send_unit_data`, and the
scanner's `handle_frame` seam. The deferred-findings docs list what to pick up.

