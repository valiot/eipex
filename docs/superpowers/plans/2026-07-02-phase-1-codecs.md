# Eipex Phase 1 — Pure Protocol Codecs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement every pure encode/decode function for EtherNet/IP + CIP (encapsulation, CPF, EPATH, Message Router, CIP types, Connection Manager, Logix services), validated against real byte vectors.

**Architecture:** Layer 0 of the approved spec (`docs/superpowers/specs/2026-07-02-ethernet-ip-stack-design.md`): pure functions over binaries, no processes, no sockets. Everything is little-endian except the `sockaddr` structures embedded in CPF items and the ListIdentity response, which are big-endian. Later phases (scanner/adapter processes) consume these codecs unchanged.

**Tech Stack:** Elixir ≥ 1.15 / OTP ≥ 26 (managed via mise), ExUnit, StreamData (test-only).

**Reference:** `docs/research/protocol-byte-layouts.md` holds every layout and the 14 known implementation traps. Each task below cites the relevant section. Read it before implementing the task.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. Test-only deps allowed (`stream_data`).
- All multi-byte fields little-endian **except** sockaddr structs (big-endian) — trap #1.
- Codecs never raise on malformed input: return `{:error, reason}`. `decode` of a stream may return `:partial`.
- Run `mix format` before every commit.
- Every commit appends one line to `CHANGELOG.md`: format `[Type] What changed`, max 100 chars, no rationale.
- TDD: write the failing test first, watch it fail, implement, watch it pass, commit.

## File Structure

```
eipex/
├── mise.toml                        # elixir/erlang versions
├── mix.exs                          # package eipex, deps: stream_data (test)
├── CHANGELOG.md
├── README.md                        # one-paragraph stub
├── lib/eipex/
│   ├── encap.ex                     # Task 1-2: encapsulation header + commands
│   ├── identity.ex                  # Task 3: %Eipex.Identity{} (shared by both roles later)
│   ├── cpf.ex                       # Task 3: Common Packet Format items
│   └── cip/
│       ├── path.ex                  # Task 4: EPATH segments
│       ├── message_router.ex        # Task 5: MR request/response + status codes
│       ├── types.ex                 # Task 6: CIP elementary types + Logix symbol type
│       ├── connection_manager.ex    # Task 7: FO/LFO/FC/UnconnectedSend
│       └── logix.ex                 # Task 8: tag services, MSP, Symbol/Template objects
└── test/eipex/                      # mirrors lib/, one test file per module
```

---

### Task 1: Project scaffold + encapsulation header codec

**Files:**
- Create: `mise.toml`, `mix.exs` (via `mix new`), `CHANGELOG.md`, `README.md`, `.gitignore`
- Create: `lib/eipex/encap.ex`
- Test: `test/eipex/encap_test.exs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `%Eipex.Encap{command: atom, session_handle: non_neg_integer, status: non_neg_integer, sender_context: <<_::64>>, options: non_neg_integer, data: binary}`
  - `Eipex.Encap.encode(%Eipex.Encap{}) :: binary`
  - `Eipex.Encap.decode(binary) :: {:ok, %Eipex.Encap{}, rest :: binary} | :partial | {:error, {:unknown_command, integer}}`
  - `Eipex.Encap.status_name(non_neg_integer) :: atom`

- [ ] **Step 1: Scaffold the project**

```bash
cd /home/alde/Documents/Elixir/repos/eipex
mix new . --module Eipex --app eipex
```

Then create `mise.toml`:

```toml
[tools]
erlang = "27"
elixir = "1.18"
```

(If mise is not installed and the system Elixir is ≥ 1.15, proceed with it; `mise.toml` still documents the intended toolchain.)

Edit `mix.exs` — set metadata and the test-only dep:

```elixir
defmodule Eipex.MixProject do
  use Mix.Project

  def project do
    [
      app: :eipex,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "EtherNet/IP (CIP) protocol stack: scanner and adapter roles",
      package: [licenses: ["Apache-2.0"], links: %{}]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:dev, :test]}
    ]
  end
end
```

Create `CHANGELOG.md`:

```markdown
# Changelog

## v0.1.0-dev

- [Added] Project scaffold with mise toolchain and test-only StreamData dependency
```

Create `README.md`:

```markdown
# Eipex

EtherNet/IP (CIP) protocol stack in pure Elixir: scanner (originator) and
adapter (target) roles, explicit and implicit messaging, and Logix tag
services. Design: `docs/superpowers/specs/2026-07-02-ethernet-ip-stack-design.md`.
```

Delete the generated placeholder test and trim the root module now (the root
module gets real content in later phases):

```bash
rm test/eipex_test.exs
```

Replace `lib/eipex.ex` with:

```elixir
defmodule Eipex do
  @moduledoc """
  EtherNet/IP (CIP) protocol stack: scanner (originator) and adapter (target).
  """
end
```

Run: `mix deps.get && mix test`
Expected: `0 failures, 0 tests`.

- [ ] **Step 2: Write the failing header codec test**

`test/eipex/encap_test.exs` — vectors from research §1 (24-byte header, RegisterSession example):

```elixir
defmodule Eipex.EncapTest do
  use ExUnit.Case, async: true

  alias Eipex.Encap

  # RegisterSession request: command 0x65, length 4, session 0, status 0,
  # zeroed context/options, data = protocol version 1 + flags 0.
  @register_session_frame <<0x65, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0x01, 0x00, 0x00, 0x00>>

  test "encodes a RegisterSession frame" do
    frame = %Encap{command: :register_session, data: <<1::16-little, 0::16-little>>}
    assert Encap.encode(frame) == @register_session_frame
  end

  test "decodes a RegisterSession frame" do
    assert {:ok, %Encap{command: :register_session, session_handle: 0, status: 0,
                        data: <<1::16-little, 0::16-little>>}, <<>>} =
             Encap.decode(@register_session_frame)
  end

  test "decode keeps trailing bytes as rest (TCP stream reassembly)" do
    assert {:ok, %Encap{command: :register_session}, <<0xAB>>} =
             Encap.decode(@register_session_frame <> <<0xAB>>)
  end

  test "decode returns :partial for incomplete header or body" do
    assert :partial = Encap.decode(binary_part(@register_session_frame, 0, 10))
    assert :partial = Encap.decode(binary_part(@register_session_frame, 0, 26))
  end

  test "decode rejects unknown commands without raising" do
    bogus = <<0xFF, 0xFF, 0::16, 0::32, 0::32, 0::64, 0::32>>
    assert {:error, {:unknown_command, 0xFFFF}} = Encap.decode(bogus)
  end

  test "round-trips every command" do
    for cmd <- [:nop, :list_services, :list_identity, :list_interfaces,
                :register_session, :unregister_session, :send_rr_data, :send_unit_data] do
      frame = %Encap{command: cmd, session_handle: 0x11223344, data: <<1, 2, 3>>}
      assert {:ok, ^frame, <<>>} = frame |> Encap.encode() |> Encap.decode()
    end
  end

  test "status_name maps encapsulation status codes" do
    assert Encap.status_name(0x0000) == :success
    assert Encap.status_name(0x0001) == :invalid_command
    assert Encap.status_name(0x0002) == :insufficient_memory
    assert Encap.status_name(0x0003) == :incorrect_data
    assert Encap.status_name(0x0064) == :invalid_session_handle
    assert Encap.status_name(0x0065) == :invalid_length
    assert Encap.status_name(0x0069) == :unsupported_protocol_version
    assert Encap.status_name(0x1234) == :unknown
  end
end
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `mix test test/eipex/encap_test.exs`
Expected: FAIL — `Eipex.Encap.__struct__/1 is undefined`.

- [ ] **Step 4: Implement `Eipex.Encap`**

`lib/eipex/encap.ex`:

```elixir
defmodule Eipex.Encap do
  @moduledoc """
  EtherNet/IP encapsulation layer codec: the fixed 24-byte header and its
  commands (CIP Vol 2). All fields little-endian.
  """

  defstruct command: nil,
            session_handle: 0,
            status: 0,
            sender_context: <<0::64>>,
            options: 0,
            data: <<>>

  @type t :: %__MODULE__{}

  @commands [
    nop: 0x0000,
    list_services: 0x0004,
    list_identity: 0x0063,
    list_interfaces: 0x0064,
    register_session: 0x0065,
    unregister_session: 0x0066,
    send_rr_data: 0x006F,
    send_unit_data: 0x0070
  ]

  @statuses %{
    0x0000 => :success,
    0x0001 => :invalid_command,
    0x0002 => :insufficient_memory,
    0x0003 => :incorrect_data,
    0x0064 => :invalid_session_handle,
    0x0065 => :invalid_length,
    0x0069 => :unsupported_protocol_version
  }

  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = frame) do
    code = Keyword.fetch!(@commands, frame.command)

    <<code::16-little, byte_size(frame.data)::16-little,
      frame.session_handle::32-little, frame.status::32-little,
      frame.sender_context::binary-size(8), frame.options::32-little,
      frame.data::binary>>
  end

  @spec decode(binary()) :: {:ok, t(), binary()} | :partial | {:error, {:unknown_command, integer()}}
  def decode(<<code::16-little, length::16-little, session::32-little,
               status::32-little, context::binary-size(8), options::32-little,
               rest::binary>>) do
    case {command_name(code), rest} do
      {nil, _} ->
        {:error, {:unknown_command, code}}

      {command, <<data::binary-size(length), tail::binary>>} ->
        {:ok,
         %__MODULE__{command: command, session_handle: session, status: status,
                     sender_context: context, options: options, data: data}, tail}

      _short ->
        :partial
    end
  end

  def decode(bin) when is_binary(bin), do: :partial

  @spec status_name(non_neg_integer()) :: atom()
  def status_name(code), do: Map.get(@statuses, code, :unknown)

  defp command_name(code) do
    Enum.find_value(@commands, fn {name, c} -> if c == code, do: name end)
  end
end
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `mix test test/eipex/encap_test.exs`
Expected: PASS, 7 tests, 0 failures.

- [ ] **Step 6: Format and commit**

Append to `CHANGELOG.md` under `v0.1.0-dev`:

```markdown
- [Added] Encapsulation header codec with the 8 EtherNet/IP commands and status codes
```

```bash
mix format
git add -A
git commit -m "feat: project scaffold and encapsulation header codec"
```

---

### Task 2: Encapsulation command payload builders

**Files:**
- Modify: `lib/eipex/encap.ex`
- Test: `test/eipex/encap_test.exs` (append)

**Interfaces:**
- Consumes: `Eipex.Encap` struct/encode/decode from Task 1.
- Produces:
  - `Eipex.Encap.register_session() :: t()` — command `:register_session`, data `<<1::16-little, 0::16-little>>`
  - `Eipex.Encap.unregister_session(session_handle) :: t()`
  - `Eipex.Encap.nop() :: t()`
  - `Eipex.Encap.list_identity() :: t()` (session 0, no data — usable over UDP broadcast)
  - `Eipex.Encap.send_rr_data(session_handle, cpf_binary, timeout \\ 0) :: t()` — data = interface handle (4B, =0) + timeout (2B) + CPF
  - `Eipex.Encap.send_unit_data(session_handle, cpf_binary) :: t()` — same 6-byte prefix, timeout must be 0 for connected
  - `Eipex.Encap.unwrap_cpf(t()) :: {:ok, cpf_binary} | {:error, :bad_interface_data}` — strips the 6-byte prefix of SendRRData/SendUnitData

- [ ] **Step 1: Write the failing tests (append to `test/eipex/encap_test.exs`)**

```elixir
  describe "command builders" do
    test "register_session carries protocol version 1" do
      assert %Encap{command: :register_session, session_handle: 0,
                    data: <<1, 0, 0, 0>>} = Encap.register_session()
    end

    test "unregister_session carries the session handle, no data" do
      assert %Encap{command: :unregister_session, session_handle: 0xCAFE, data: <<>>} =
               Encap.unregister_session(0xCAFE)
    end

    test "list_identity is sessionless and empty" do
      assert %Encap{command: :list_identity, session_handle: 0, data: <<>>} =
               Encap.list_identity()
    end

    test "send_rr_data prefixes interface handle 0 and timeout" do
      cpf = <<0xDE, 0xAD>>
      frame = Encap.send_rr_data(0x1234, cpf, 10)
      assert frame.command == :send_rr_data
      assert frame.session_handle == 0x1234
      assert frame.data == <<0::32-little, 10::16-little, 0xDE, 0xAD>>
    end

    test "send_unit_data uses timeout 0" do
      frame = Encap.send_unit_data(0x1234, <<0xBE, 0xEF>>)
      assert frame.data == <<0::32-little, 0::16-little, 0xBE, 0xEF>>
    end

    test "unwrap_cpf strips the 6-byte interface prefix" do
      frame = Encap.send_rr_data(1, <<1, 2, 3>>)
      assert {:ok, <<1, 2, 3>>} = Encap.unwrap_cpf(frame)
      assert {:error, :bad_interface_data} = Encap.unwrap_cpf(%Encap{command: :send_rr_data, data: <<1>>})
    end
  end
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `mix test test/eipex/encap_test.exs`
Expected: FAIL — `Encap.register_session/0 is undefined`; the Task 1 tests still pass.

- [ ] **Step 3: Implement the builders (append inside `Eipex.Encap`)**

```elixir
  @protocol_version 1

  @spec register_session() :: t()
  def register_session do
    %__MODULE__{command: :register_session,
                data: <<@protocol_version::16-little, 0::16-little>>}
  end

  @spec unregister_session(non_neg_integer()) :: t()
  def unregister_session(session_handle) do
    %__MODULE__{command: :unregister_session, session_handle: session_handle}
  end

  @spec nop() :: t()
  def nop, do: %__MODULE__{command: :nop}

  @spec list_identity() :: t()
  def list_identity, do: %__MODULE__{command: :list_identity}

  @spec send_rr_data(non_neg_integer(), binary(), non_neg_integer()) :: t()
  def send_rr_data(session_handle, cpf, timeout \\ 0) do
    %__MODULE__{command: :send_rr_data, session_handle: session_handle,
                data: <<0::32-little, timeout::16-little, cpf::binary>>}
  end

  @spec send_unit_data(non_neg_integer(), binary()) :: t()
  def send_unit_data(session_handle, cpf) do
    %__MODULE__{command: :send_unit_data, session_handle: session_handle,
                data: <<0::32-little, 0::16-little, cpf::binary>>}
  end

  @spec unwrap_cpf(t()) :: {:ok, binary()} | {:error, :bad_interface_data}
  def unwrap_cpf(%__MODULE__{data: <<_iface::32, _timeout::16, cpf::binary>>}), do: {:ok, cpf}
  def unwrap_cpf(%__MODULE__{}), do: {:error, :bad_interface_data}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/encap_test.exs`
Expected: PASS, 13 tests, 0 failures.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Encapsulation command builders (RegisterSession, SendRRData, SendUnitData, ListIdentity)`

```bash
mix format && git add -A && git commit -m "feat: encapsulation command payload builders"
```

---

### Task 3: Common Packet Format (CPF) + Identity item

**Files:**
- Create: `lib/eipex/cpf.ex`, `lib/eipex/identity.ex`
- Test: `test/eipex/cpf_test.exs`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure).
- Produces:
  - `Eipex.CPF.encode([item]) :: binary` and `Eipex.CPF.decode(binary) :: {:ok, [item]} | {:error, :malformed_cpf}` where `item` is:
    - `:null_address`
    - `{:connected_address, conn_id :: non_neg_integer}`
    - `{:sequenced_address, conn_id :: non_neg_integer, seq :: non_neg_integer}`
    - `{:unconnected_data, binary}` | `{:connected_data, binary}`
    - `{:sockaddr_o2t, %{ip: :inet.ip4_address(), port: non_neg_integer}}` | `{:sockaddr_t2o, ...}`
    - `{:identity, %Eipex.Identity{}}` (decode only)
    - `{:unknown, type_code :: non_neg_integer, binary}` (decode only — forward compatible)
  - `%Eipex.Identity{protocol_version, ip, port, vendor_id, device_type, product_code, revision: {major, minor}, status, serial_number, product_name, state}`
  - `Eipex.Identity.decode_item(binary) :: {:ok, %Eipex.Identity{}} | {:error, :malformed_identity}`
  - `Eipex.Identity.encode_item(%Eipex.Identity{}) :: binary` (the adapter's ListIdentity reply body, without the CPF item header)

**Trap #1 applies here:** inside sockaddr and the Identity item, `sin_family`, `sin_port`, `sin_addr` are **big-endian**; everything around them stays little-endian. See research §1.

- [ ] **Step 1: Write the failing tests**

`test/eipex/cpf_test.exs`:

```elixir
defmodule Eipex.CPFTest do
  use ExUnit.Case, async: true

  alias Eipex.{CPF, Identity}

  test "encodes UCMM pair: null address + unconnected data" do
    assert CPF.encode([:null_address, {:unconnected_data, <<0xAA, 0xBB>>}]) ==
             <<2::16-little, 0x0000::16-little, 0::16-little,
               0x00B2::16-little, 2::16-little, 0xAA, 0xBB>>
  end

  test "encodes connected pair with address item" do
    assert CPF.encode([{:connected_address, 0x0102_0304}, {:connected_data, <<1>>}]) ==
             <<2::16-little, 0x00A1::16-little, 4::16-little, 0x0102_0304::32-little,
               0x00B1::16-little, 1::16-little, 1>>
  end

  test "encodes sequenced address item for class 1 I/O" do
    assert CPF.encode([{:sequenced_address, 0xCAFE, 7}, {:connected_data, <<9>>}]) ==
             <<2::16-little, 0x8002::16-little, 8::16-little,
               0xCAFE::32-little, 7::32-little, 0x00B1::16-little, 1::16-little, 9>>
  end

  test "sockaddr items are big-endian inside a little-endian frame" do
    item = {:sockaddr_t2o, %{ip: {192, 168, 1, 10}, port: 2222}}

    assert CPF.encode([item]) ==
             <<1::16-little, 0x8001::16-little, 16::16-little,
               2::16-big, 2222::16-big, 192, 168, 1, 10, 0::64>>

    assert {:ok, [^item]} = CPF.decode(CPF.encode([item]))
  end

  test "round-trips every item type" do
    items = [
      :null_address,
      {:connected_address, 1},
      {:sequenced_address, 2, 3},
      {:unconnected_data, <<1, 2>>},
      {:connected_data, <<3>>},
      {:sockaddr_o2t, %{ip: {10, 0, 0, 1}, port: 2222}}
    ]

    assert {:ok, ^items} = items |> CPF.encode() |> CPF.decode()
  end

  test "decode tolerates unknown item types" do
    bin = <<1::16-little, 0x00FF::16-little, 2::16-little, 7, 8>>
    assert {:ok, [{:unknown, 0x00FF, <<7, 8>>}]} = CPF.decode(bin)
  end

  test "decode rejects truncated items without raising" do
    assert {:error, :malformed_cpf} = CPF.decode(<<2::16-little, 0x00B2::16-little, 9::16-little, 1>>)
  end

  # ListIdentity response item body (research §1): version 1, sockaddr (BE),
  # vendor 0x004D, type 0x0C, product 0x77, rev 1.2, status 0, serial 0x99,
  # name "Eipex", state 3.
  @identity_body <<1::16-little, 2::16-big, 44818::16-big, 10, 0, 0, 5, 0::64,
                   0x4D::16-little, 0x0C::16-little, 0x77::16-little, 1, 2,
                   0::16-little, 0x99::32-little, 5, "Eipex", 3>>

  test "decodes a ListIdentity identity item via CPF" do
    cpf = <<1::16-little, 0x000C::16-little, byte_size(@identity_body)::16-little,
            @identity_body::binary>>

    assert {:ok, [{:identity, %Identity{vendor_id: 0x4D, device_type: 0x0C,
                                        product_code: 0x77, revision: {1, 2},
                                        serial_number: 0x99, product_name: "Eipex",
                                        ip: {10, 0, 0, 5}, port: 44818, state: 3}}]} =
             CPF.decode(cpf)
  end

  test "identity item round-trips" do
    {:ok, [{:identity, id}]} =
      CPF.decode(<<1::16-little, 0x000C::16-little,
                   byte_size(@identity_body)::16-little, @identity_body::binary>>)

    assert Identity.encode_item(id) == @identity_body
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cpf_test.exs`
Expected: FAIL — `Eipex.CPF.encode/1 is undefined`.

- [ ] **Step 3: Implement `Eipex.Identity` and `Eipex.CPF`**

`lib/eipex/identity.ex`:

```elixir
defmodule Eipex.Identity do
  @moduledoc """
  The Identity item (type 0x000C) carried in ListIdentity responses.
  sockaddr fields are big-endian (network order); the rest is little-endian.
  """

  defstruct protocol_version: 1,
            ip: {0, 0, 0, 0},
            port: 44_818,
            vendor_id: 0,
            device_type: 0,
            product_code: 0,
            revision: {1, 0},
            status: 0,
            serial_number: 0,
            product_name: "",
            state: 0

  @type t :: %__MODULE__{}

  @spec decode_item(binary()) :: {:ok, t()} | {:error, :malformed_identity}
  def decode_item(<<version::16-little, _family::16-big, port::16-big,
                    a, b, c, d, _zero::64, vendor::16-little, type::16-little,
                    product::16-little, major, minor, status::16-little,
                    serial::32-little, name_len, name::binary-size(name_len),
                    state>>) do
    {:ok,
     %__MODULE__{protocol_version: version, ip: {a, b, c, d}, port: port,
                 vendor_id: vendor, device_type: type, product_code: product,
                 revision: {major, minor}, status: status, serial_number: serial,
                 product_name: name, state: state}}
  end

  def decode_item(_), do: {:error, :malformed_identity}

  @spec encode_item(t()) :: binary()
  def encode_item(%__MODULE__{ip: {a, b, c, d}, revision: {major, minor}} = id) do
    <<id.protocol_version::16-little, 2::16-big, id.port::16-big, a, b, c, d,
      0::64, id.vendor_id::16-little, id.device_type::16-little,
      id.product_code::16-little, major, minor, id.status::16-little,
      id.serial_number::32-little, byte_size(id.product_name),
      id.product_name::binary, id.state>>
  end
end
```

`lib/eipex/cpf.ex`:

```elixir
defmodule Eipex.CPF do
  @moduledoc """
  Common Packet Format: item count + (type, length, data) items.
  Carried inside SendRRData/SendUnitData and class 1 UDP datagrams.
  """

  alias Eipex.Identity

  @type item ::
          :null_address
          | {:connected_address, non_neg_integer()}
          | {:sequenced_address, non_neg_integer(), non_neg_integer()}
          | {:unconnected_data, binary()}
          | {:connected_data, binary()}
          | {:sockaddr_o2t, %{ip: :inet.ip4_address(), port: non_neg_integer()}}
          | {:sockaddr_t2o, %{ip: :inet.ip4_address(), port: non_neg_integer()}}
          | {:identity, Identity.t()}
          | {:unknown, non_neg_integer(), binary()}

  @spec encode([item()]) :: binary()
  def encode(items) do
    body = Enum.map_join(items, &encode_item/1)
    <<length(items)::16-little, body::binary>>
  end

  defp encode_item(:null_address), do: <<0x0000::16-little, 0::16-little>>

  defp encode_item({:connected_address, id}),
    do: <<0x00A1::16-little, 4::16-little, id::32-little>>

  defp encode_item({:sequenced_address, id, seq}),
    do: <<0x8002::16-little, 8::16-little, id::32-little, seq::32-little>>

  defp encode_item({:unconnected_data, data}),
    do: <<0x00B2::16-little, byte_size(data)::16-little, data::binary>>

  defp encode_item({:connected_data, data}),
    do: <<0x00B1::16-little, byte_size(data)::16-little, data::binary>>

  defp encode_item({:sockaddr_o2t, sa}), do: encode_sockaddr(0x8000, sa)
  defp encode_item({:sockaddr_t2o, sa}), do: encode_sockaddr(0x8001, sa)

  defp encode_item({:identity, %Identity{} = id}) do
    body = Identity.encode_item(id)
    <<0x000C::16-little, byte_size(body)::16-little, body::binary>>
  end

  defp encode_sockaddr(type, %{ip: {a, b, c, d}, port: port}) do
    <<type::16-little, 16::16-little, 2::16-big, port::16-big, a, b, c, d, 0::64>>
  end

  @spec decode(binary()) :: {:ok, [item()]} | {:error, :malformed_cpf}
  def decode(<<count::16-little, body::binary>>), do: decode_items(body, count, [])
  def decode(_), do: {:error, :malformed_cpf}

  defp decode_items(<<>>, 0, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_items(_rest, 0, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_items(<<type::16-little, len::16-little, data::binary-size(len),
                      rest::binary>>, n, acc) do
    case decode_item(type, data) do
      {:ok, item} -> decode_items(rest, n - 1, [item | acc])
      :error -> {:error, :malformed_cpf}
    end
  end

  defp decode_items(_, _, _), do: {:error, :malformed_cpf}

  defp decode_item(0x0000, <<>>), do: {:ok, :null_address}
  defp decode_item(0x00A1, <<id::32-little>>), do: {:ok, {:connected_address, id}}

  defp decode_item(0x8002, <<id::32-little, seq::32-little>>),
    do: {:ok, {:sequenced_address, id, seq}}

  defp decode_item(0x00B2, data), do: {:ok, {:unconnected_data, data}}
  defp decode_item(0x00B1, data), do: {:ok, {:connected_data, data}}

  defp decode_item(type, <<_family::16-big, port::16-big, a, b, c, d, _::64>>)
       when type in [0x8000, 0x8001] do
    tag = if type == 0x8000, do: :sockaddr_o2t, else: :sockaddr_t2o
    {:ok, {tag, %{ip: {a, b, c, d}, port: port}}}
  end

  defp decode_item(0x000C, data) do
    case Identity.decode_item(data) do
      {:ok, id} -> {:ok, {:identity, id}}
      {:error, _} -> :error
    end
  end

  defp decode_item(type, data), do: {:ok, {:unknown, type, data}}
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cpf_test.exs`
Expected: PASS, 9 tests, 0 failures.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] CPF item codec and ListIdentity identity item (big-endian sockaddr handling)`

```bash
mix format && git add -A && git commit -m "feat: CPF codec and identity item"
```

---

### Task 4: EPATH codec

**Files:**
- Create: `lib/eipex/cip/path.ex`
- Test: `test/eipex/cip/path_test.exs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `Eipex.CIP.Path.encode(segments) :: binary` — padded EPATH. `segments` is a list of:
    - `{:class, n}` | `{:instance, n}` | `{:attribute, n}` | `{:member, n}` | `{:connection_point, n}` (8/16-bit format chosen automatically; member also supports 32-bit)
    - `{:symbolic, "TagName"}` (ANSI extended, 0x91, padded to even length)
    - `{:port, port_number, link_address}` (e.g. `{:port, 1, 0}` = backplane slot 0)
  - `Eipex.CIP.Path.decode(binary) :: {:ok, segments} | {:error, :malformed_path}`
  - `Eipex.CIP.Path.words(binary) :: non_neg_integer` — `div(byte_size, 2)`, the size unit used by Message Router and connection paths.

**Traps #2 applies:** symbolic segments with odd-length names take one 0x00 pad byte; 16/32-bit logical formats insert a 0x00 pad after the type byte. Research §2.

- [ ] **Step 1: Write the failing tests**

`test/eipex/cip/path_test.exs` — vectors straight from research §2 and §7:

```elixir
defmodule Eipex.CIP.PathTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.Path

  test "message router path: class 0x02 instance 1 (8-bit)" do
    assert Path.encode(class: 0x02, instance: 0x01) == <<0x20, 0x02, 0x24, 0x01>>
  end

  test "16-bit instance inserts a pad byte after the type byte" do
    # Symbol Object class 0x6B, instance 0xF68F (1756-PM020 example)
    assert Path.encode(class: 0x6B, instance: 0xF68F) ==
             <<0x20, 0x6B, 0x25, 0x00, 0x8F, 0xF6>>
  end

  test "even-length symbolic segment has no pad" do
    assert Path.encode(symbolic: "TotalCount") ==
             <<0x91, 0x0A, "TotalCount">>
  end

  test "odd-length symbolic segment is padded to a word boundary" do
    assert Path.encode(symbolic: "ports") == <<0x91, 0x05, "ports", 0x00>>
  end

  test "port segment routes to backplane slot" do
    assert Path.encode([{:port, 1, 0}, {:class, 0x02}, {:instance, 1}]) ==
             <<0x01, 0x00, 0x20, 0x02, 0x24, 0x01>>
  end

  test "attribute and member segments" do
    assert Path.encode(class: 0x01, instance: 1, attribute: 7) ==
             <<0x20, 0x01, 0x24, 0x01, 0x30, 0x07>>

    assert Path.encode(symbolic: "Struct.M", member: 3) ==
             <<0x91, 0x08, "Struct.M", 0x28, 0x03>>
  end

  test "words/1 counts 16-bit words" do
    assert Path.words(Path.encode(class: 0x02, instance: 1)) == 2
  end

  test "decode round-trips logical, symbolic and port segments" do
    segs = [{:port, 1, 0}, {:class, 0x6B}, {:instance, 0xF68F}, {:attribute, 2}]
    assert {:ok, ^segs} = segs |> Path.encode() |> Path.decode()

    segs2 = [{:symbolic, "ports"}, {:member, 3}]
    assert {:ok, ^segs2} = segs2 |> Path.encode() |> Path.decode()
  end

  test "decode rejects garbage without raising" do
    assert {:error, :malformed_path} = Path.decode(<<0x91, 0x09, "abc">>)
    assert {:error, :malformed_path} = Path.decode(<<0xFF, 0x00>>)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/path_test.exs`
Expected: FAIL — `Eipex.CIP.Path.encode/1 is undefined`.

- [ ] **Step 3: Implement `Eipex.CIP.Path`**

`lib/eipex/cip/path.ex`:

```elixir
defmodule Eipex.CIP.Path do
  @moduledoc """
  Padded EPATH codec: logical segments (8/16/32-bit), ANSI extended symbolic
  segments (0x91, padded to even length) and port segments for routing.
  """

  @logical_types [class: 0x20, instance: 0x24, attribute: 0x30,
                  member: 0x28, connection_point: 0x2C]

  @type segment ::
          {:class | :instance | :attribute | :member | :connection_point, non_neg_integer()}
          | {:symbolic, String.t()}
          | {:port, non_neg_integer(), non_neg_integer()}

  @spec encode([segment()]) :: binary()
  def encode(segments), do: Enum.map_join(segments, &encode_segment/1)

  defp encode_segment({:symbolic, name}) do
    pad = if rem(byte_size(name), 2) == 1, do: <<0>>, else: <<>>
    <<0x91, byte_size(name), name::binary, pad::binary>>
  end

  defp encode_segment({:port, port, link}) when port <= 14 and link < 256 do
    <<port, link>>
  end

  defp encode_segment({type, value}) when value < 256 do
    <<Keyword.fetch!(@logical_types, type), value>>
  end

  defp encode_segment({type, value}) when value < 65_536 do
    <<Keyword.fetch!(@logical_types, type) + 1, 0x00, value::16-little>>
  end

  defp encode_segment({:member, value}) do
    <<0x2A, 0x00, value::32-little>>
  end

  @spec words(binary()) :: non_neg_integer()
  def words(path) when is_binary(path), do: div(byte_size(path), 2)

  @spec decode(binary()) :: {:ok, [segment()]} | {:error, :malformed_path}
  def decode(bin), do: decode_segments(bin, [])

  defp decode_segments(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_segments(<<0x91, len, name::binary-size(len), rest::binary>>, acc) do
    rest = if rem(len, 2) == 1, do: strip_pad(rest), else: rest

    case rest do
      {:error, _} = err -> err
      rest -> decode_segments(rest, [{:symbolic, name} | acc])
    end
  end

  defp decode_segments(<<type, value, rest::binary>>, acc)
       when type in [0x20, 0x24, 0x28, 0x2C, 0x30] do
    decode_segments(rest, [{logical_name(type), value} | acc])
  end

  defp decode_segments(<<type, 0x00, value::16-little, rest::binary>>, acc)
       when type in [0x21, 0x25, 0x29, 0x2D, 0x31] do
    decode_segments(rest, [{logical_name(type - 1), value} | acc])
  end

  defp decode_segments(<<0x2A, 0x00, value::32-little, rest::binary>>, acc) do
    decode_segments(rest, [{:member, value} | acc])
  end

  defp decode_segments(<<port, link, rest::binary>>, acc) when port <= 14 do
    decode_segments(rest, [{:port, port, link} | acc])
  end

  defp decode_segments(_, _), do: {:error, :malformed_path}

  defp strip_pad(<<0x00, rest::binary>>), do: rest
  defp strip_pad(<<>>), do: <<>>
  defp strip_pad(_), do: {:error, :malformed_path}

  defp logical_name(code) do
    Enum.find_value(@logical_types, fn {name, c} -> if c == code, do: name end)
  end
end
```

**Note for the implementer:** the port-segment decode clause is ambiguous with
logical segments by design of the protocol (a port segment's first byte 0x01
cannot be confused with 0x20+ type bytes, so ordering the clauses as above is
what makes decode deterministic: logical and symbolic clauses match first).

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/path_test.exs`
Expected: PASS, 9 tests, 0 failures.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] EPATH codec: logical, symbolic and port segments with spec padding`

```bash
mix format && git add -A && git commit -m "feat: EPATH segment codec"
```

---

### Task 5: Message Router request/response codec

**Files:**
- Create: `lib/eipex/cip/message_router.ex`
- Test: `test/eipex/cip/message_router_test.exs`

**Interfaces:**
- Consumes: `Eipex.CIP.Path.encode/1`, `Eipex.CIP.Path.words/1` (Task 4).
- Produces:
  - `Eipex.CIP.MessageRouter.encode_request(service :: byte, path :: binary | [Path.segment()], data :: binary) :: binary`
  - `Eipex.CIP.MessageRouter.decode_request(binary) :: {:ok, %{service: byte, path: binary, data: binary}} | {:error, :malformed_request}` (adapter side; `path` stays binary — the object layer decodes it)
  - `Eipex.CIP.MessageRouter.encode_response(service :: byte, status :: byte, opts) :: binary` — opts: `data:` (default `<<>>`), `extended:` (list of 16-bit words, default `[]`)
  - `Eipex.CIP.MessageRouter.decode_response(binary) :: {:ok, %{service: byte, status: byte, status_name: atom, extended: [non_neg_integer], data: binary}} | {:error, :malformed_response}`
  - `Eipex.CIP.MessageRouter.status_name(byte) :: atom` — the general status table from research §2.

- [ ] **Step 1: Write the failing tests**

`test/eipex/cip/message_router_test.exs` — the Read Tag vector from 1756-PM020:

```elixir
defmodule Eipex.CIP.MessageRouterTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.MessageRouter, as: MR

  # 1756-PM020: Read Tag "TotalCount", 1 element
  @read_request <<0x4C, 0x06, 0x91, 0x0A, "TotalCount", 0x01, 0x00>>
  # Reply: service|0x80, reserved, status 0, ext size 0, DINT type + value 534
  @read_reply <<0xCC, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>

  test "encodes a request with a segment list path" do
    assert MR.encode_request(0x4C, [symbolic: "TotalCount"], <<1::16-little>>) ==
             @read_request
  end

  test "encodes a request with a pre-encoded binary path" do
    path = Eipex.CIP.Path.encode(symbolic: "TotalCount")
    assert MR.encode_request(0x4C, path, <<1::16-little>>) == @read_request
  end

  test "decodes a request (adapter side)" do
    assert {:ok, %{service: 0x4C, path: path, data: <<1, 0>>}} =
             MR.decode_request(@read_request)

    assert {:ok, [symbolic: "TotalCount"]} = Eipex.CIP.Path.decode(path)
  end

  test "decodes a success response" do
    assert {:ok, %{service: 0x4C, status: 0x00, status_name: :success,
                   extended: [], data: <<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>}} =
             MR.decode_response(@read_reply)
  end

  test "encodes a success response" do
    assert MR.encode_response(0x4C, 0x00, data: <<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>) ==
             @read_reply
  end

  test "encodes and decodes an error response with extended status" do
    bin = MR.encode_response(0x54, 0x01, extended: [0x0100])

    assert bin == <<0xD4, 0x00, 0x01, 0x01, 0x00, 0x01>>

    assert {:ok, %{status: 0x01, status_name: :connection_failure,
                   extended: [0x0100], data: <<>>}} = MR.decode_response(bin)
  end

  test "status_name covers the CIP general status table" do
    assert MR.status_name(0x00) == :success
    assert MR.status_name(0x04) == :path_segment_error
    assert MR.status_name(0x05) == :path_destination_unknown
    assert MR.status_name(0x06) == :partial_transfer
    assert MR.status_name(0x08) == :service_not_supported
    assert MR.status_name(0x13) == :not_enough_data
    assert MR.status_name(0x14) == :attribute_not_supported
    assert MR.status_name(0x1E) == :embedded_service_error
    assert MR.status_name(0x26) == :path_size_invalid
    assert MR.status_name(0xF9) == :unknown
  end

  test "malformed inputs return errors, never raise" do
    assert {:error, :malformed_request} = MR.decode_request(<<0x4C, 0x09, 0x91>>)
    assert {:error, :malformed_response} = MR.decode_response(<<0xCC, 0x00, 0x00>>)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/message_router_test.exs`
Expected: FAIL — `MessageRouter.encode_request/3 is undefined`.

- [ ] **Step 3: Implement `Eipex.CIP.MessageRouter`**

`lib/eipex/cip/message_router.ex`:

```elixir
defmodule Eipex.CIP.MessageRouter do
  @moduledoc """
  CIP Message Router request/response framing and the general status table.
  Request: service, path size (words), padded EPATH, service data.
  Response: service | 0x80, reserved 0, general status, extended words, data.
  """

  alias Eipex.CIP.Path

  @statuses %{
    0x00 => :success,
    0x01 => :connection_failure,
    0x02 => :resource_unavailable,
    0x03 => :invalid_parameter_value,
    0x04 => :path_segment_error,
    0x05 => :path_destination_unknown,
    0x06 => :partial_transfer,
    0x07 => :connection_lost,
    0x08 => :service_not_supported,
    0x09 => :invalid_attribute_value,
    0x0A => :attribute_list_error,
    0x0B => :already_in_state,
    0x0C => :object_state_conflict,
    0x0D => :object_already_exists,
    0x0E => :attribute_not_settable,
    0x0F => :privilege_violation,
    0x10 => :device_state_conflict,
    0x11 => :reply_data_too_large,
    0x13 => :not_enough_data,
    0x14 => :attribute_not_supported,
    0x15 => :too_much_data,
    0x16 => :object_does_not_exist,
    0x1E => :embedded_service_error,
    0x1F => :vendor_specific_error,
    0x20 => :invalid_parameter,
    0x26 => :path_size_invalid,
    0x2C => :attribute_not_gettable,
    0xFF => :general_error
  }

  @spec encode_request(byte(), binary() | [Path.segment()], binary()) :: binary()
  def encode_request(service, path, data \\ <<>>)

  def encode_request(service, path, data) when is_list(path),
    do: encode_request(service, Path.encode(path), data)

  def encode_request(service, path, data) when is_binary(path) do
    <<service, Path.words(path), path::binary, data::binary>>
  end

  @spec decode_request(binary()) ::
          {:ok, %{service: byte(), path: binary(), data: binary()}}
          | {:error, :malformed_request}
  def decode_request(<<service, words, path::binary-size(words * 2), data::binary>>) do
    {:ok, %{service: service, path: path, data: data}}
  end

  def decode_request(_), do: {:error, :malformed_request}

  @spec encode_response(byte(), byte(), keyword()) :: binary()
  def encode_response(service, status, opts \\ []) do
    data = Keyword.get(opts, :data, <<>>)
    extended = Keyword.get(opts, :extended, [])
    ext_bin = for word <- extended, into: <<>>, do: <<word::16-little>>

    <<Bitwise.bor(service, 0x80), 0x00, status, length(extended),
      ext_bin::binary, data::binary>>
  end

  @spec decode_response(binary()) ::
          {:ok, %{service: byte(), status: byte(), status_name: atom(),
                  extended: [non_neg_integer()], data: binary()}}
          | {:error, :malformed_response}
  def decode_response(<<reply_service, 0x00, status, ext_words,
                        ext::binary-size(ext_words * 2), data::binary>>) do
    extended = for <<word::16-little <- ext>>, do: word

    {:ok,
     %{service: Bitwise.band(reply_service, 0x7F), status: status,
       status_name: status_name(status), extended: extended, data: data}}
  end

  def decode_response(_), do: {:error, :malformed_response}

  @spec status_name(byte()) :: atom()
  def status_name(code), do: Map.get(@statuses, code, :unknown)
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/message_router_test.exs`
Expected: PASS, 8 tests, 0 failures.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Message Router request/response codec with CIP general status table`

```bash
mix format && git add -A && git commit -m "feat: message router codec"
```

---

### Task 6: CIP data types + Logix symbol type

**Files:**
- Create: `lib/eipex/cip/types.ex`
- Test: `test/eipex/cip/types_test.exs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `Eipex.CIP.Types.type_code(atom) :: non_neg_integer` — `:bool 0xC1, :sint 0xC2, :int 0xC3, :dint 0xC4, :lint 0xC5, :usint 0xC6, :uint 0xC7, :udint 0xC8, :ulint 0xC9, :real 0xCA, :lreal 0xCB, :byte 0xD1, :word 0xD2, :dword 0xD3, :lword 0xD4, :short_string 0xDA`
  - `Eipex.CIP.Types.type_name(non_neg_integer) :: atom | :unknown`
  - `Eipex.CIP.Types.encode(atom, term) :: {:ok, binary} | {:error, :bad_value}` — value only, no type prefix
  - `Eipex.CIP.Types.decode(atom, binary) :: {:ok, term} | {:error, :bad_value}` — exact-size match; multi-element data handled by callers
  - `Eipex.CIP.Types.decode_typed(binary) :: {:ok, {type :: atom, values :: term | [term]}, meta} | {:ok, {:struct, handle, data}} | {:error, :bad_value}` — parses Logix read-reply data: `<<type::16-little, payload>>`, or `<<0xA0, 0x02, handle::16-little, payload>>` for structures; returns a list when payload holds multiple elements
  - `Eipex.CIP.Types.decode_symbol_type(<<_::16>> | non_neg_integer) :: %{structure?: boolean, system?: boolean, dims: 0..3, atomic_type: atom | nil, template_instance: non_neg_integer | nil, bool_position: 0..7 | nil}`

**Trap #3:** the Logix STRING type is not CIP STRING 0xD0 — it is a struct (`DINT len + SINT[82]`). This codec does not special-case it; Task 8's template layer detects string-shaped structures. Research §2 and §7.

- [ ] **Step 1: Write the failing tests**

`test/eipex/cip/types_test.exs`:

```elixir
defmodule Eipex.CIP.TypesTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.Types

  test "type codes match the CIP table" do
    assert Types.type_code(:dint) == 0xC4
    assert Types.type_code(:real) == 0xCA
    assert Types.type_name(0xC3) == :int
    assert Types.type_name(0x1234) == :unknown
  end

  test "encodes and decodes atomic values" do
    assert {:ok, <<0x16, 0x02, 0x00, 0x00>>} = Types.encode(:dint, 534)
    assert {:ok, 534} = Types.decode(:dint, <<0x16, 0x02, 0x00, 0x00>>)

    assert {:ok, <<0xFF>>} = Types.encode(:sint, -1)
    assert {:ok, -1} = Types.decode(:sint, <<0xFF>>)

    assert {:ok, bin} = Types.encode(:real, 1.5)
    assert {:ok, 1.5} = Types.decode(:real, bin)

    assert {:ok, <<1>>} = Types.encode(:bool, true)
    assert {:ok, false} = Types.decode(:bool, <<0>>)
  end

  test "decode rejects size mismatches without raising" do
    assert {:error, :bad_value} = Types.decode(:dint, <<1, 2>>)
    assert {:error, :bad_value} = Types.encode(:sint, 40_000)
  end

  test "decode_typed parses a Logix read reply payload" do
    assert {:ok, {:dint, 534}} = Types.decode_typed(<<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>)
    # two-element array of INT
    assert {:ok, {:int, [7, 8]}} = Types.decode_typed(<<0xC3, 0x00, 7, 0, 8, 0>>)
    # structure: 0x02A0 marker + template handle + raw data
    assert {:ok, {:struct, 0x0FAB, <<1, 2, 3>>}} =
             Types.decode_typed(<<0xA0, 0x02, 0xAB, 0x0F, 1, 2, 3>>)
  end

  test "decode_symbol_type: atomic DINT" do
    assert %{structure?: false, system?: false, dims: 0, atomic_type: :dint,
             template_instance: nil, bool_position: nil} =
             Types.decode_symbol_type(0x00C4)
  end

  test "decode_symbol_type: 1-dim array of REAL" do
    # bit 13 set = 1 dimension
    assert %{structure?: false, dims: 1, atomic_type: :real} =
             Types.decode_symbol_type(0x20CA)
  end

  test "decode_symbol_type: structure with template instance" do
    # bit 15 set, bits 11-0 = template instance 0x2E9
    assert %{structure?: true, template_instance: 0x2E9, atomic_type: nil} =
             Types.decode_symbol_type(0x82E9)
  end

  test "decode_symbol_type: system tag and BOOL bit position" do
    assert %{system?: true} = Types.decode_symbol_type(0x1000)
    assert %{atomic_type: :bool, bool_position: 3} = Types.decode_symbol_type(0x03C1)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/types_test.exs`
Expected: FAIL — `Types.type_code/1 is undefined`.

- [ ] **Step 3: Implement `Eipex.CIP.Types`**

`lib/eipex/cip/types.ex`:

```elixir
defmodule Eipex.CIP.Types do
  @moduledoc """
  CIP elementary data type codec and the Logix 16-bit symbol type decoder
  (1756-PM020). Structures arrive as `0x02A0` + template handle; their
  interpretation needs the Template object (see Eipex.CIP.Logix).
  """

  @codes [
    bool: 0xC1, sint: 0xC2, int: 0xC3, dint: 0xC4, lint: 0xC5,
    usint: 0xC6, uint: 0xC7, udint: 0xC8, ulint: 0xC9,
    real: 0xCA, lreal: 0xCB,
    byte: 0xD1, word: 0xD2, dword: 0xD3, lword: 0xD4,
    short_string: 0xDA
  ]

  @spec type_code(atom()) :: non_neg_integer()
  def type_code(name), do: Keyword.fetch!(@codes, name)

  @spec type_name(non_neg_integer()) :: atom()
  def type_name(code) do
    Enum.find_value(@codes, :unknown, fn {name, c} -> if c == code, do: name end)
  end

  @spec encode(atom(), term()) :: {:ok, binary()} | {:error, :bad_value}
  def encode(:bool, true), do: {:ok, <<1>>}
  def encode(:bool, false), do: {:ok, <<0>>}
  def encode(:sint, v) when v in -128..127, do: {:ok, <<v::8-signed>>}
  def encode(:int, v) when v in -32_768..32_767, do: {:ok, <<v::16-little-signed>>}
  def encode(:dint, v) when v in -2_147_483_648..2_147_483_647, do: {:ok, <<v::32-little-signed>>}
  def encode(:lint, v) when is_integer(v), do: {:ok, <<v::64-little-signed>>}
  def encode(:usint, v) when v in 0..255, do: {:ok, <<v::8>>}
  def encode(:uint, v) when v in 0..65_535, do: {:ok, <<v::16-little>>}
  def encode(:udint, v) when v in 0..4_294_967_295, do: {:ok, <<v::32-little>>}
  def encode(:ulint, v) when is_integer(v) and v >= 0, do: {:ok, <<v::64-little>>}
  def encode(:real, v) when is_number(v), do: {:ok, <<v::32-little-float>>}
  def encode(:lreal, v) when is_number(v), do: {:ok, <<v::64-little-float>>}
  def encode(:byte, v) when v in 0..255, do: {:ok, <<v::8>>}
  def encode(:word, v) when v in 0..65_535, do: {:ok, <<v::16-little>>}
  def encode(:dword, v) when v in 0..4_294_967_295, do: {:ok, <<v::32-little>>}
  def encode(:lword, v) when is_integer(v) and v >= 0, do: {:ok, <<v::64-little>>}
  def encode(:short_string, s) when is_binary(s) and byte_size(s) < 256,
    do: {:ok, <<byte_size(s), s::binary>>}
  def encode(_, _), do: {:error, :bad_value}

  @spec decode(atom(), binary()) :: {:ok, term()} | {:error, :bad_value}
  def decode(:bool, <<0>>), do: {:ok, false}
  def decode(:bool, <<_>>), do: {:ok, true}
  def decode(:sint, <<v::8-signed>>), do: {:ok, v}
  def decode(:int, <<v::16-little-signed>>), do: {:ok, v}
  def decode(:dint, <<v::32-little-signed>>), do: {:ok, v}
  def decode(:lint, <<v::64-little-signed>>), do: {:ok, v}
  def decode(:usint, <<v::8>>), do: {:ok, v}
  def decode(:uint, <<v::16-little>>), do: {:ok, v}
  def decode(:udint, <<v::32-little>>), do: {:ok, v}
  def decode(:ulint, <<v::64-little>>), do: {:ok, v}
  def decode(:real, <<v::32-little-float>>), do: {:ok, v}
  def decode(:lreal, <<v::64-little-float>>), do: {:ok, v}
  def decode(:byte, <<v::8>>), do: {:ok, v}
  def decode(:word, <<v::16-little>>), do: {:ok, v}
  def decode(:dword, <<v::32-little>>), do: {:ok, v}
  def decode(:lword, <<v::64-little>>), do: {:ok, v}
  def decode(:short_string, <<len, s::binary-size(len)>>), do: {:ok, s}
  def decode(_, _), do: {:error, :bad_value}

  @doc "Parses `<<type::16-little, payload>>` from Logix read replies."
  @spec decode_typed(binary()) ::
          {:ok, {atom(), term()} | {:struct, non_neg_integer(), binary()}}
          | {:error, :bad_value}
  def decode_typed(<<0xA0, 0x02, handle::16-little, data::binary>>),
    do: {:ok, {:struct, handle, data}}

  def decode_typed(<<0xDA, 0x00, payload::binary>>) do
    case decode(:short_string, payload) do
      {:ok, s} -> {:ok, {:short_string, s}}
      error -> error
    end
  end

  def decode_typed(<<code::16-little, payload::binary>>) do
    with name when name != :unknown <- type_name(code),
         {:ok, values} <- decode_elements(name, payload, []) do
      case values do
        [single] -> {:ok, {name, single}}
        many -> {:ok, {name, many}}
      end
    else
      _ -> {:error, :bad_value}
    end
  end

  def decode_typed(_), do: {:error, :bad_value}

  defp decode_elements(_name, <<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_elements(name, payload, acc) do
    size = element_size(name)

    case payload do
      <<chunk::binary-size(size), rest::binary>> ->
        {:ok, value} = decode(name, chunk)
        decode_elements(name, rest, [value | acc])

      _ ->
        {:error, :bad_value}
    end
  end

  defp element_size(name) when name in [:bool, :sint, :usint, :byte], do: 1
  defp element_size(name) when name in [:int, :uint, :word], do: 2
  defp element_size(name) when name in [:dint, :udint, :dword, :real], do: 4
  defp element_size(name) when name in [:lint, :ulint, :lword, :lreal], do: 8

  @doc "Decodes the Logix 16-bit symbol type word (1756-PM020 p.50)."
  @spec decode_symbol_type(non_neg_integer() | <<_::16>>) :: map()
  def decode_symbol_type(<<value::16-little>>), do: decode_symbol_type(value)

  def decode_symbol_type(value) when is_integer(value) do
    import Bitwise

    structure? = (value &&& 0x8000) != 0
    system? = (value &&& 0x1000) != 0
    dims = value >>> 13 &&& 0x3

    if structure? do
      %{structure?: true, system?: system?, dims: dims,
        atomic_type: nil, template_instance: value &&& 0x0FFF, bool_position: nil}
    else
      code = value &&& 0xFF
      atomic = type_name(code)

      bool_position =
        if atomic == :bool, do: value >>> 8 &&& 0x7

      %{structure?: false, system?: system?, dims: dims,
        atomic_type: atomic, template_instance: nil, bool_position: bool_position}
    end
  end
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/types_test.exs`
Expected: PASS, 8 tests, 0 failures.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] CIP elementary type codec and Logix 16-bit symbol type decoder`

```bash
mix format && git add -A && git commit -m "feat: CIP data types codec"
```

---

### Task 7: Connection Manager codec (Forward Open / Close / Unconnected Send)

**Files:**
- Create: `lib/eipex/cip/connection_manager.ex`
- Test: `test/eipex/cip/connection_manager_test.exs`

**Interfaces:**
- Consumes: `Eipex.CIP.MessageRouter.encode_request/3` (Task 5), `Eipex.CIP.Path.encode/1|words/1` (Task 4).
- Produces:
  - `%Eipex.CIP.ConnectionManager.ForwardOpen{priority_time_tick, timeout_ticks, o2t_connection_id, t2o_connection_id, connection_serial, originator_vendor_id, originator_serial, timeout_multiplier, o2t_rpi, o2t_params, t2o_rpi, t2o_params, transport, connection_path}` — `o2t_params`/`t2o_params` are `%{owner: :exclusive | :redundant, type: :null | :multicast | :point_to_point, priority: :low | :high | :scheduled | :urgent, size_type: :fixed | :variable, size: non_neg_integer}`; `transport` is `%{direction: :client | :server, trigger: :cyclic | :change_of_state | :application, class: 0..3}`; `connection_path` is a binary EPATH.
  - `ConnectionManager.encode_params(:standard | :large, params_map) :: binary` / `decode_params(variant, binary) :: params_map` — the 16/32-bit network connection parameter words
  - `ConnectionManager.encode_transport(transport_map) :: binary` / `decode_transport(<<_::8>>) :: transport_map`
  - `ConnectionManager.encode_forward_open(%ForwardOpen{}, :standard | :large) :: binary` — complete MR request (service 0x54/0x5B, path `[class: 0x06, instance: 1]`)
  - `ConnectionManager.decode_forward_open(service :: 0x54 | 0x5B, data :: binary) :: {:ok, %ForwardOpen{}} | {:error, :malformed_forward_open}` (adapter side, takes MR-decoded `service` + `data`)
  - `%ConnectionManager.ForwardOpenReply{o2t_connection_id, t2o_connection_id, connection_serial, originator_vendor_id, originator_serial, o2t_api, t2o_api, application_reply}`
  - `ConnectionManager.encode_forward_open_reply(%ForwardOpenReply{}) :: binary` (adapter) / `decode_forward_open_reply(binary) :: {:ok, %ForwardOpenReply{}} | {:error, :malformed_reply}` (scanner)
  - `ConnectionManager.encode_forward_close(triad :: %{connection_serial, originator_vendor_id, originator_serial}, connection_path :: binary, opts) :: binary` (MR request, service 0x4E) / `decode_forward_close(data) :: {:ok, triad_and_path} | {:error, _}`
  - `ConnectionManager.encode_unconnected_send(embedded_mr_request :: binary, route_path :: [Path.segment()], opts) :: binary` — MR request (service 0x52) with the odd-length pad byte (trap #2)
  - `ConnectionManager.ext_status_name(non_neg_integer) :: atom` — 0x0100 `:connection_in_use`, 0x0106 `:ownership_conflict`, 0x0111 `:rpi_not_supported`, 0x0113 `:out_of_connections`, 0x0127 `:invalid_o2t_size`, 0x0128 `:invalid_t2o_size`, 0x0129 `:invalid_config_path`, 0x012A `:invalid_consuming_path`, 0x012B `:invalid_producing_path`, 0x0315 `:invalid_segment_type`
  - `ConnectionManager.timeout_factor(code :: 0..7) :: pos_integer` — `4 * 2^code` (watchdog = RPI × factor)

Layouts in research §3. **Trap #11:** RPIs are microseconds.

- [ ] **Step 1: Write the failing tests**

`test/eipex/cip/connection_manager_test.exs`:

```elixir
defmodule Eipex.CIP.ConnectionManagerTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.ConnectionManager.{ForwardOpen, ForwardOpenReply}
  alias Eipex.CIP.Path

  defp sample_fo do
    %ForwardOpen{
      priority_time_tick: 0x0A, timeout_ticks: 5,
      o2t_connection_id: 0, t2o_connection_id: 0x1122_3344,
      connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001, timeout_multiplier: 1,
      o2t_rpi: 10_000,
      o2t_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                    size_type: :variable, size: 500},
      t2o_rpi: 10_000,
      t2o_params: %{owner: :exclusive, type: :point_to_point, priority: :low,
                    size_type: :variable, size: 500},
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(class: 0x02, instance: 1)
    }
  end

  test "network params bit layout, 16-bit (standard FO)" do
    params = %{owner: :exclusive, type: :point_to_point, priority: :low,
               size_type: :variable, size: 500}
    # p2p = 2<<13 (0x4000), variable = 1<<9 (0x0200), size 500 = 0x1F4 → 0x45F4
    assert CM.encode_params(:standard, params) == <<0xF4, 0x45>>
    assert CM.decode_params(:standard, <<0xF4, 0x45>>) == params
  end

  test "network params bit layout, 32-bit (large FO)" do
    params = %{owner: :exclusive, type: :point_to_point, priority: :low,
               size_type: :variable, size: 4002}
    # p2p = 2<<29, variable = 1<<25, size 4002 = 0x0FA2 → 0x42000FA2
    assert CM.encode_params(:large, params) == <<0xA2, 0x0F, 0x00, 0x42>>
    assert CM.decode_params(:large, <<0xA2, 0x0F, 0x00, 0x42>>) == params
  end

  test "transport class/trigger byte" do
    assert CM.encode_transport(%{direction: :server, trigger: :cyclic, class: 1}) == <<0x81>>
    assert CM.encode_transport(%{direction: :client, trigger: :application, class: 3}) == <<0x23>>
    assert CM.decode_transport(<<0x81>>) == %{direction: :server, trigger: :cyclic, class: 1}
  end

  test "forward open request round-trips (standard and large)" do
    fo = sample_fo()

    for variant <- [:standard, :large] do
      request = CM.encode_forward_open(fo, variant)
      service = if variant == :standard, do: 0x54, else: 0x5B

      assert {:ok, %{service: ^service, data: data}} =
               Eipex.CIP.MessageRouter.decode_request(request)

      assert {:ok, ^fo} = CM.decode_forward_open(service, data)
    end
  end

  test "forward open request targets the connection manager object" do
    assert <<0x54, 0x02, 0x20, 0x06, 0x24, 0x01, _::binary>> =
             CM.encode_forward_open(sample_fo(), :standard)
  end

  test "forward open reply round-trips" do
    reply = %ForwardOpenReply{
      o2t_connection_id: 0xAAAA_0001, t2o_connection_id: 0x1122_3344,
      connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001, o2t_api: 10_000, t2o_api: 10_000,
      application_reply: <<>>
    }

    assert {:ok, ^reply} = reply |> CM.encode_forward_open_reply() |> CM.decode_forward_open_reply()
  end

  test "forward close carries the triad and path" do
    triad = %{connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
              originator_serial: 0xDEAD_0001}
    path = Path.encode(class: 0x02, instance: 1)
    request = CM.encode_forward_close(triad, path, [])

    assert {:ok, %{service: 0x4E, data: data}} =
             Eipex.CIP.MessageRouter.decode_request(request)

    assert {:ok, %{connection_serial: 0xBEEF, originator_vendor_id: 0x004D,
                   originator_serial: 0xDEAD_0001, connection_path: ^path}} =
             CM.decode_forward_close(data)
  end

  test "unconnected send pads odd embedded messages (trap #2)" do
    # 11-byte embedded request (odd): 2 header + 6 path + 3 data
    embedded = Eipex.CIP.MessageRouter.encode_request(0x4C, [symbolic: "abc"], <<1, 2, 3>>)
    assert rem(byte_size(embedded), 2) == 1

    request = CM.encode_unconnected_send(embedded, [{:port, 1, 0}], [])
    {:ok, %{service: 0x52, data: data}} = Eipex.CIP.MessageRouter.decode_request(request)

    size = byte_size(embedded)

    # after the embedded message: pad 0x00, route words 1, reserved 0x00,
    # route path <<0x01, 0x00>> (backplane slot 0)
    assert <<_ptt, _ticks, ^size::16-little, ^embedded::binary-size(size),
             0x00, 0x01, 0x00, 0x01, 0x00>> = data
  end

  test "extended status names and timeout factor" do
    assert CM.ext_status_name(0x0100) == :connection_in_use
    assert CM.ext_status_name(0x0106) == :ownership_conflict
    assert CM.ext_status_name(0x0113) == :out_of_connections
    assert CM.ext_status_name(0x9999) == :unknown
    assert CM.timeout_factor(0) == 4
    assert CM.timeout_factor(2) == 16
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/connection_manager_test.exs`
Expected: FAIL — `ForwardOpen.__struct__/1 is undefined`.

- [ ] **Step 3: Implement `Eipex.CIP.ConnectionManager`**

`lib/eipex/cip/connection_manager.ex`:

```elixir
defmodule Eipex.CIP.ConnectionManager do
  @moduledoc """
  Connection Manager (class 0x06) service codecs: Forward Open (0x54),
  Large Forward Open (0x5B), Forward Close (0x4E), Unconnected Send (0x52).
  RPIs are in microseconds (trap #11).
  """

  import Bitwise

  alias Eipex.CIP.{MessageRouter, Path}

  @cm_path [class: 0x06, instance: 0x01]

  defmodule ForwardOpen do
    defstruct priority_time_tick: 0x0A, timeout_ticks: 5,
              o2t_connection_id: 0, t2o_connection_id: 0,
              connection_serial: 0, originator_vendor_id: 0, originator_serial: 0,
              timeout_multiplier: 1, o2t_rpi: 1_000_000, o2t_params: nil,
              t2o_rpi: 1_000_000, t2o_params: nil, transport: nil,
              connection_path: <<>>

    @type t :: %__MODULE__{}
  end

  defmodule ForwardOpenReply do
    defstruct o2t_connection_id: 0, t2o_connection_id: 0, connection_serial: 0,
              originator_vendor_id: 0, originator_serial: 0,
              o2t_api: 0, t2o_api: 0, application_reply: <<>>

    @type t :: %__MODULE__{}
  end

  @ext_statuses %{
    0x0100 => :connection_in_use,
    0x0106 => :ownership_conflict,
    0x0110 => :target_not_configured,
    0x0111 => :rpi_not_supported,
    0x0113 => :out_of_connections,
    0x0123 => :invalid_o2t_type,
    0x0124 => :invalid_t2o_type,
    0x0127 => :invalid_o2t_size,
    0x0128 => :invalid_t2o_size,
    0x0129 => :invalid_config_path,
    0x012A => :invalid_consuming_path,
    0x012B => :invalid_producing_path,
    0x0315 => :invalid_segment_type
  }

  # -- Network connection parameters ------------------------------------------

  @conn_types [null: 0, multicast: 1, point_to_point: 2]
  @priorities [low: 0, high: 1, scheduled: 2, urgent: 3]

  @spec encode_params(:standard | :large, map()) :: binary()
  def encode_params(:standard, p) do
    value =
      owner_bit(p.owner) <<< 15 ||| Keyword.fetch!(@conn_types, p.type) <<< 13 |||
        Keyword.fetch!(@priorities, p.priority) <<< 10 |||
        size_bit(p.size_type) <<< 9 ||| (p.size &&& 0x1FF)

    <<value::16-little>>
  end

  def encode_params(:large, p) do
    value =
      owner_bit(p.owner) <<< 31 ||| Keyword.fetch!(@conn_types, p.type) <<< 29 |||
        Keyword.fetch!(@priorities, p.priority) <<< 26 |||
        size_bit(p.size_type) <<< 25 ||| (p.size &&& 0xFFFF)

    <<value::32-little>>
  end

  @spec decode_params(:standard | :large, binary()) :: map()
  def decode_params(:standard, <<value::16-little>>) do
    %{owner: owner_name(value >>> 15 &&& 1),
      type: conn_type_name(value >>> 13 &&& 0x3),
      priority: priority_name(value >>> 10 &&& 0x3),
      size_type: size_name(value >>> 9 &&& 1),
      size: value &&& 0x1FF}
  end

  def decode_params(:large, <<value::32-little>>) do
    %{owner: owner_name(value >>> 31 &&& 1),
      type: conn_type_name(value >>> 29 &&& 0x3),
      priority: priority_name(value >>> 26 &&& 0x3),
      size_type: size_name(value >>> 25 &&& 1),
      size: value &&& 0xFFFF}
  end

  defp owner_bit(:exclusive), do: 0
  defp owner_bit(:redundant), do: 1
  defp owner_name(0), do: :exclusive
  defp owner_name(1), do: :redundant
  defp size_bit(:fixed), do: 0
  defp size_bit(:variable), do: 1
  defp size_name(0), do: :fixed
  defp size_name(1), do: :variable

  defp conn_type_name(v), do: Enum.find_value(@conn_types, fn {n, c} -> if c == v, do: n end)
  defp priority_name(v), do: Enum.find_value(@priorities, fn {n, c} -> if c == v, do: n end)

  # -- Transport class/trigger -------------------------------------------------

  @triggers [cyclic: 0, change_of_state: 1, application: 2]

  @spec encode_transport(map()) :: binary()
  def encode_transport(%{direction: dir, trigger: trigger, class: class}) do
    dir_bit = if dir == :server, do: 1, else: 0
    <<dir_bit <<< 7 ||| Keyword.fetch!(@triggers, trigger) <<< 4 ||| class>>
  end

  @spec decode_transport(binary()) :: map()
  def decode_transport(<<byte>>) do
    %{direction: (if (byte &&& 0x80) != 0, do: :server, else: :client),
      trigger: Enum.find_value(@triggers, fn {n, c} -> if c == (byte >>> 4 &&& 0x7), do: n end),
      class: byte &&& 0xF}
  end

  # -- Forward Open ------------------------------------------------------------

  @spec encode_forward_open(ForwardOpen.t(), :standard | :large) :: binary()
  def encode_forward_open(%ForwardOpen{} = fo, variant) do
    service = if variant == :standard, do: 0x54, else: 0x5B

    data =
      <<fo.priority_time_tick, fo.timeout_ticks,
        fo.o2t_connection_id::32-little, fo.t2o_connection_id::32-little,
        fo.connection_serial::16-little, fo.originator_vendor_id::16-little,
        fo.originator_serial::32-little, fo.timeout_multiplier, 0, 0, 0,
        fo.o2t_rpi::32-little, encode_params(variant, fo.o2t_params)::binary,
        fo.t2o_rpi::32-little, encode_params(variant, fo.t2o_params)::binary,
        encode_transport(fo.transport)::binary,
        Path.words(fo.connection_path), fo.connection_path::binary>>

    MessageRouter.encode_request(service, @cm_path, data)
  end

  @spec decode_forward_open(0x54 | 0x5B, binary()) ::
          {:ok, ForwardOpen.t()} | {:error, :malformed_forward_open}
  def decode_forward_open(service, data) when service in [0x54, 0x5B] do
    {variant, params_size} = if service == 0x54, do: {:standard, 2}, else: {:large, 4}

    with <<ptt, ticks, o2t_id::32-little, t2o_id::32-little, serial::16-little,
           vendor::16-little, orig_serial::32-little, multiplier, _::24,
           o2t_rpi::32-little, o2t_p::binary-size(params_size),
           t2o_rpi::32-little, t2o_p::binary-size(params_size),
           transport::binary-size(1), path_words,
           path::binary-size(path_words * 2)>> <- data do
      {:ok,
       %ForwardOpen{priority_time_tick: ptt, timeout_ticks: ticks,
                    o2t_connection_id: o2t_id, t2o_connection_id: t2o_id,
                    connection_serial: serial, originator_vendor_id: vendor,
                    originator_serial: orig_serial, timeout_multiplier: multiplier,
                    o2t_rpi: o2t_rpi, o2t_params: decode_params(variant, o2t_p),
                    t2o_rpi: t2o_rpi, t2o_params: decode_params(variant, t2o_p),
                    transport: decode_transport(transport), connection_path: path}}
    else
      _ -> {:error, :malformed_forward_open}
    end
  end

  @spec encode_forward_open_reply(ForwardOpenReply.t()) :: binary()
  def encode_forward_open_reply(%ForwardOpenReply{} = r) do
    reply_words = div(byte_size(r.application_reply), 2)

    <<r.o2t_connection_id::32-little, r.t2o_connection_id::32-little,
      r.connection_serial::16-little, r.originator_vendor_id::16-little,
      r.originator_serial::32-little, r.o2t_api::32-little, r.t2o_api::32-little,
      reply_words, 0, r.application_reply::binary>>
  end

  @spec decode_forward_open_reply(binary()) ::
          {:ok, ForwardOpenReply.t()} | {:error, :malformed_reply}
  def decode_forward_open_reply(<<o2t::32-little, t2o::32-little, serial::16-little,
                                  vendor::16-little, orig_serial::32-little,
                                  o2t_api::32-little, t2o_api::32-little,
                                  reply_words, _reserved,
                                  reply::binary-size(reply_words * 2)>>) do
    {:ok,
     %ForwardOpenReply{o2t_connection_id: o2t, t2o_connection_id: t2o,
                       connection_serial: serial, originator_vendor_id: vendor,
                       originator_serial: orig_serial, o2t_api: o2t_api,
                       t2o_api: t2o_api, application_reply: reply}}
  end

  def decode_forward_open_reply(_), do: {:error, :malformed_reply}

  # -- Forward Close -----------------------------------------------------------

  @spec encode_forward_close(map(), binary(), keyword()) :: binary()
  def encode_forward_close(triad, connection_path, opts) do
    data =
      <<Keyword.get(opts, :priority_time_tick, 0x0A), Keyword.get(opts, :timeout_ticks, 5),
        triad.connection_serial::16-little, triad.originator_vendor_id::16-little,
        triad.originator_serial::32-little,
        Path.words(connection_path), 0, connection_path::binary>>

    MessageRouter.encode_request(0x4E, @cm_path, data)
  end

  @spec decode_forward_close(binary()) :: {:ok, map()} | {:error, :malformed_forward_close}
  def decode_forward_close(<<_ptt, _ticks, serial::16-little, vendor::16-little,
                             orig_serial::32-little, path_words, _reserved,
                             path::binary-size(path_words * 2)>>) do
    {:ok,
     %{connection_serial: serial, originator_vendor_id: vendor,
       originator_serial: orig_serial, connection_path: path}}
  end

  def decode_forward_close(_), do: {:error, :malformed_forward_close}

  # -- Unconnected Send --------------------------------------------------------

  @spec encode_unconnected_send(binary(), [Path.segment()], keyword()) :: binary()
  def encode_unconnected_send(embedded, route_path, opts) do
    pad = if rem(byte_size(embedded), 2) == 1, do: <<0x00>>, else: <<>>
    route = Path.encode(route_path)

    data =
      <<Keyword.get(opts, :priority_time_tick, 0x0A), Keyword.get(opts, :timeout_ticks, 5),
        byte_size(embedded)::16-little, embedded::binary, pad::binary,
        Path.words(route), 0x00, route::binary>>

    MessageRouter.encode_request(0x52, @cm_path, data)
  end

  # -- Helpers -----------------------------------------------------------------

  @spec ext_status_name(non_neg_integer()) :: atom()
  def ext_status_name(code), do: Map.get(@ext_statuses, code, :unknown)

  @spec timeout_factor(0..7) :: pos_integer()
  def timeout_factor(code), do: 4 <<< code
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/connection_manager_test.exs`
Expected: PASS, 9 tests, 0 failures.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Connection Manager codec: Forward Open/Close, Unconnected Send, connection params`

```bash
mix format && git add -A && git commit -m "feat: connection manager codec"
```

---

### Task 8: Logix services codec (tags, MSP, Symbol/Template objects)

**Files:**
- Create: `lib/eipex/cip/logix.ex`
- Test: `test/eipex/cip/logix_test.exs`

**Interfaces:**
- Consumes: `MessageRouter.encode_request/3|decode_response/1` (Task 5), `Path.encode/1` (Task 4), `Types.decode_symbol_type/1` (Task 6).
- Produces (all requests are complete MR request binaries; responses take the `data` field of `MessageRouter.decode_response/1`):
  - `Eipex.CIP.Logix.encode_read_tag(path, elements \\ 1)` — service 0x4C; `path` is `[Path.segment()]` or binary
  - `Eipex.CIP.Logix.encode_read_tag_fragmented(path, elements, byte_offset)` — 0x52; offset in **bytes** (trap #12)
  - `Eipex.CIP.Logix.encode_write_tag(path, type_prefix :: binary, elements, data)` — 0x4D; `type_prefix` is `<<code::16-little>>` or `<<0xA0, 0x02, handle::16-little>>` (trap #4)
  - `Eipex.CIP.Logix.encode_write_tag_fragmented(path, type_prefix, elements, byte_offset, data)` — 0x53
  - `Eipex.CIP.Logix.encode_rmw(path, or_mask :: binary, and_mask :: binary)` — 0x4E; mask sizes must be equal and in [1, 2, 4, 8, 12]
  - `Eipex.CIP.Logix.encode_multiple_service([mr_request_binary])` — 0x0A to `[class: 0x02, instance: 1]` with the offset table
  - `Eipex.CIP.Logix.decode_multiple_service_reply(data) :: {:ok, [embedded_reply :: binary]} | {:error, :malformed_msp}`
  - `Eipex.CIP.Logix.encode_symbol_list(start_instance \\ 0)` — 0x55 on `[class: 0x6B, instance: start]`, attributes 1 (name) + 2 (type)
  - `Eipex.CIP.Logix.decode_symbol_list(data) :: {:ok, [%{instance: n, name: String.t(), symbol_type: map, raw_type: n}]} | {:error, :malformed_symbol_list}` — caller decides continuation from MR status (0x06 = more)
  - `Eipex.CIP.Logix.encode_template_attributes(template_instance)` — Get_Attribute_List (0x03) on class 0x6C for attrs 4, 5, 2, 1
  - `Eipex.CIP.Logix.decode_template_attributes(data) :: {:ok, %{handle, member_count, definition_size, structure_size}} | {:error, _}`
  - `Eipex.CIP.Logix.encode_read_template(template_instance, byte_offset, bytes)` — 0x4C on class 0x6C
  - `Eipex.CIP.Logix.decode_template_definition(binary, member_count) :: {:ok, %{name: String.t(), members: [%{name, info, raw_type, symbol_type, offset}]}} | {:error, _}` — caller accumulates 0x06 fragments first; byte count to request = `definition_size * 4 - 23` (research §7)

- [ ] **Step 1: Write the failing tests**

`test/eipex/cip/logix_test.exs` — byte vectors from 1756-PM020 (research §7):

```elixir
defmodule Eipex.CIP.LogixTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.Logix

  test "read tag: TotalCount, 1 element (manual example)" do
    assert Logix.encode_read_tag([symbolic: "TotalCount"]) ==
             <<0x4C, 0x06, 0x91, 0x0A, "TotalCount", 0x01, 0x00>>
  end

  test "read tag fragmented appends a 4-byte offset" do
    assert Logix.encode_read_tag_fragmented([symbolic: "TotalCount"], 1, 490) ==
             <<0x52, 0x06, 0x91, 0x0A, "TotalCount", 0x01, 0x00, 490::32-little>>
  end

  test "write tag: CartonSize = 14 as DINT (manual example)" do
    assert Logix.encode_write_tag([symbolic: "CartonSize"], <<0xC4, 0x00>>, 1,
             <<0x0E, 0x00, 0x00, 0x00>>) ==
             <<0x4D, 0x06, 0x91, 0x0A, "CartonSize", 0xC4, 0x00, 0x01, 0x00,
               0x0E, 0x00, 0x00, 0x00>>
  end

  test "read-modify-write: set bit 2, clear bit 5 of ControlWord (manual example)" do
    assert Logix.encode_rmw([symbolic: "ControlWord"],
             <<0x04, 0x00, 0x00, 0x00>>, <<0xDF, 0xFF, 0xFF, 0xFF>>) ==
             <<0x4E, 0x07, 0x91, 0x0B, "ControlWord", 0x00, 0x04, 0x00,
               0x04, 0x00, 0x00, 0x00, 0xDF, 0xFF, 0xFF, 0xFF>>
  end

  test "rmw rejects invalid mask sizes" do
    assert_raise FunctionClauseError, fn ->
      Logix.encode_rmw([symbolic: "X"], <<1, 2, 3>>, <<1, 2, 3>>)
    end
  end

  test "multiple service packet builds the offset table" do
    r1 = Logix.encode_read_tag(symbolic: "AB")   # 8 bytes
    r2 = Logix.encode_read_tag(symbolic: "CDEF") # 10 bytes
    msp = Logix.encode_multiple_service([r1, r2])

    # service 0x0A, path 20 02 24 01, count 2, offsets 6 and 6+8=14
    assert <<0x0A, 0x02, 0x20, 0x02, 0x24, 0x01, 2::16-little,
             6::16-little, 14::16-little, rest::binary>> = msp

    assert rest == r1 <> r2
  end

  test "multiple service reply splits embedded replies" do
    rep1 = <<0xCC, 0x00, 0x00, 0x00, 0xC4, 0x00, 1, 0, 0, 0>>
    rep2 = <<0xCC, 0x00, 0x05, 0x00>>
    data = <<2::16-little, 6::16-little, (6 + byte_size(rep1))::16-little,
             rep1::binary, rep2::binary>>

    assert {:ok, [^rep1, ^rep2]} = Logix.decode_multiple_service_reply(data)
    assert {:error, :malformed_msp} = Logix.decode_multiple_service_reply(<<9::16-little>>)
  end

  test "symbol list request asks for attributes 1 and 2 from an instance" do
    assert Logix.encode_symbol_list(0) ==
             <<0x55, 0x03, 0x20, 0x6B, 0x25, 0x00, 0x00, 0x00,
               0x02, 0x00, 0x01, 0x00, 0x02, 0x00>>
  end

  test "symbol list reply parses instances, names and types" do
    data = <<0x10::32-little, 5::16-little, "MyTag", 0x00C4::16-little,
             0x25::32-little, 3::16-little, "Str", 0x82E9::16-little>>

    assert {:ok, [%{instance: 0x10, name: "MyTag", raw_type: 0x00C4,
                    symbol_type: %{atomic_type: :dint}},
                  %{instance: 0x25, name: "Str",
                    symbol_type: %{structure?: true, template_instance: 0x2E9}}]} =
             Logix.decode_symbol_list(data)
  end

  test "template attribute request matches the manual example" do
    assert Logix.encode_template_attributes(0x02E9) ==
             <<0x03, 0x03, 0x20, 0x6C, 0x25, 0x00, 0xE9, 0x02,
               0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00>>
  end

  test "template attribute reply parses the four attributes" do
    # count 4, then per attribute: id, status 0, value
    data = <<4::16-little,
             4::16-little, 0::16-little, 0x68::32-little,
             5::16-little, 0::16-little, 0x20::32-little,
             2::16-little, 0::16-little, 3::16-little,
             1::16-little, 0::16-little, 0x0FAB::16-little>>

    assert {:ok, %{definition_size: 0x68, structure_size: 0x20,
                   member_count: 3, handle: 0x0FAB}} =
             Logix.decode_template_attributes(data)
  end

  test "read template request carries offset and byte count" do
    assert Logix.encode_read_template(0x02E9, 0, 393) ==
             <<0x4C, 0x03, 0x20, 0x6C, 0x25, 0x00, 0xE9, 0x02,
               0::32-little, 393::16-little>>
  end

  test "template definition parses members then names" do
    # 2 members (8 bytes each), then template name ';'-terminated info,
    # then member names, all null-terminated.
    members = <<0::16-little, 0x00C1::16-little, 0::32-little,
                12::16-little, 0x00C3::16-little, 4::32-little>>
    names = <<"MyUDT;n", 0, "pilot_on", 0, "hourlyCount", 0>>

    assert {:ok, %{name: "MyUDT",
                   members: [%{name: "pilot_on", raw_type: 0x00C1, info: 0, offset: 0},
                             %{name: "hourlyCount", raw_type: 0x00C3, info: 12, offset: 4}]}} =
             Logix.decode_template_definition(members <> names, 2)
  end
end
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mix test test/eipex/cip/logix_test.exs`
Expected: FAIL — `Logix.encode_read_tag/1 is undefined`.

- [ ] **Step 3: Implement `Eipex.CIP.Logix`**

`lib/eipex/cip/logix.ex`:

```elixir
defmodule Eipex.CIP.Logix do
  @moduledoc """
  Rockwell Logix data-access services (1756-PM020): Read/Write Tag (plain and
  fragmented), Read-Modify-Write, Multiple Service Packet, and the Symbol
  (0x6B) / Template (0x6C) objects used for tag discovery and UDTs.
  Fragmented offsets are byte offsets, not element counts (trap #12).
  """

  alias Eipex.CIP.{MessageRouter, Path, Types}

  @message_router_path [class: 0x02, instance: 0x01]
  @symbol_class 0x6B
  @template_class 0x6C

  # -- Tag services ------------------------------------------------------------

  @spec encode_read_tag(binary() | [Path.segment()], pos_integer()) :: binary()
  def encode_read_tag(path, elements \\ 1) do
    MessageRouter.encode_request(0x4C, path, <<elements::16-little>>)
  end

  @spec encode_read_tag_fragmented(binary() | [Path.segment()], pos_integer(),
          non_neg_integer()) :: binary()
  def encode_read_tag_fragmented(path, elements, byte_offset) do
    MessageRouter.encode_request(0x52, path,
      <<elements::16-little, byte_offset::32-little>>)
  end

  @spec encode_write_tag(binary() | [Path.segment()], binary(), pos_integer(), binary()) ::
          binary()
  def encode_write_tag(path, type_prefix, elements, data) do
    MessageRouter.encode_request(0x4D, path,
      <<type_prefix::binary, elements::16-little, data::binary>>)
  end

  @spec encode_write_tag_fragmented(binary() | [Path.segment()], binary(),
          pos_integer(), non_neg_integer(), binary()) :: binary()
  def encode_write_tag_fragmented(path, type_prefix, elements, byte_offset, data) do
    MessageRouter.encode_request(0x53, path,
      <<type_prefix::binary, elements::16-little, byte_offset::32-little, data::binary>>)
  end

  @valid_mask_sizes [1, 2, 4, 8, 12]

  @spec encode_rmw(binary() | [Path.segment()], binary(), binary()) :: binary()
  def encode_rmw(path, or_mask, and_mask)
      when byte_size(or_mask) == byte_size(and_mask) and
             byte_size(or_mask) in @valid_mask_sizes do
    MessageRouter.encode_request(0x4E, path,
      <<byte_size(or_mask)::16-little, or_mask::binary, and_mask::binary>>)
  end

  # -- Multiple Service Packet -------------------------------------------------

  @spec encode_multiple_service([binary()]) :: binary()
  def encode_multiple_service(requests) do
    count = length(requests)
    first_offset = 2 + count * 2

    {offsets, _} =
      Enum.map_reduce(requests, first_offset, fn req, offset ->
        {<<offset::16-little>>, offset + byte_size(req)}
      end)

    data =
      <<count::16-little, IO.iodata_to_binary(offsets)::binary,
        IO.iodata_to_binary(requests)::binary>>

    MessageRouter.encode_request(0x0A, @message_router_path, data)
  end

  @spec decode_multiple_service_reply(binary()) ::
          {:ok, [binary()]} | {:error, :malformed_msp}
  def decode_multiple_service_reply(<<count::16-little,
                                      offsets_bin::binary-size(count * 2),
                                      _::binary>> = data) do
    offsets = for <<o::16-little <- offsets_bin>>, do: o
    total = byte_size(data)
    bounds = offsets ++ [total]

    replies =
      bounds
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [from, to] ->
        if to > total or from > to, do: :error, else: binary_part(data, from, to - from)
      end)

    if Enum.any?(replies, &(&1 == :error)),
      do: {:error, :malformed_msp},
      else: {:ok, replies}
  end

  def decode_multiple_service_reply(_), do: {:error, :malformed_msp}

  # -- Symbol object (tag list) ------------------------------------------------

  @spec encode_symbol_list(non_neg_integer()) :: binary()
  def encode_symbol_list(start_instance \\ 0) do
    # Instance always in 16-bit format (like pycomm3): iteration walks past 255
    # quickly and a stable path shape simplifies interop.
    path = <<0x20, @symbol_class, 0x25, 0x00, start_instance::16-little>>

    MessageRouter.encode_request(0x55, path,
      <<2::16-little, 1::16-little, 2::16-little>>)
  end

  @spec decode_symbol_list(binary()) :: {:ok, [map()]} | {:error, :malformed_symbol_list}
  def decode_symbol_list(data), do: decode_symbols(data, [])

  defp decode_symbols(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_symbols(<<instance::32-little, name_len::16-little,
                        name::binary-size(name_len), raw_type::16-little,
                        rest::binary>>, acc) do
    symbol = %{instance: instance, name: name, raw_type: raw_type,
               symbol_type: Types.decode_symbol_type(raw_type)}

    decode_symbols(rest, [symbol | acc])
  end

  defp decode_symbols(_, _), do: {:error, :malformed_symbol_list}

  # -- Template object (UDT definitions) ----------------------------------------

  @template_attrs [4, 5, 2, 1]

  @spec encode_template_attributes(non_neg_integer()) :: binary()
  def encode_template_attributes(template_instance) do
    attrs = for a <- @template_attrs, into: <<>>, do: <<a::16-little>>

    MessageRouter.encode_request(0x03,
      [class: @template_class, instance: template_instance],
      <<length(@template_attrs)::16-little, attrs::binary>>)
  end

  @spec decode_template_attributes(binary()) :: {:ok, map()} | {:error, :malformed_template}
  def decode_template_attributes(<<count::16-little, rest::binary>>) do
    decode_template_attrs(rest, count, %{})
  end

  def decode_template_attributes(_), do: {:error, :malformed_template}

  defp decode_template_attrs(_rest, 0, acc), do: {:ok, acc}

  defp decode_template_attrs(<<id::16-little, 0::16-little, rest::binary>>, n, acc) do
    {key, size} =
      case id do
        1 -> {:handle, 2}
        2 -> {:member_count, 2}
        4 -> {:definition_size, 4}
        5 -> {:structure_size, 4}
      end

    case rest do
      <<value::little-size(size * 8), tail::binary>> ->
        decode_template_attrs(tail, n - 1, Map.put(acc, key, value))

      _ ->
        {:error, :malformed_template}
    end
  end

  defp decode_template_attrs(_, _, _), do: {:error, :malformed_template}

  @spec encode_read_template(non_neg_integer(), non_neg_integer(), pos_integer()) :: binary()
  def encode_read_template(template_instance, byte_offset, bytes) do
    MessageRouter.encode_request(0x4C,
      [class: @template_class, instance: template_instance],
      <<byte_offset::32-little, bytes::16-little>>)
  end

  @spec decode_template_definition(binary(), pos_integer()) ::
          {:ok, %{name: String.t(), members: [map()]}} | {:error, :malformed_template}
  def decode_template_definition(binary, member_count) do
    meta_size = member_count * 8

    with <<meta::binary-size(meta_size), names_bin::binary>> <- binary,
         [template_name | member_names] <- split_names(names_bin, member_count + 1) do
      metas =
        for <<info::16-little, raw_type::16-little, offset::32-little <- meta>> do
          %{info: info, raw_type: raw_type,
            symbol_type: Types.decode_symbol_type(raw_type), offset: offset}
        end

      members =
        metas
        |> Enum.zip(member_names)
        |> Enum.map(fn {meta_map, name} -> Map.put(meta_map, :name, name) end)

      name = template_name |> String.split(";") |> hd()
      {:ok, %{name: name, members: members}}
    else
      _ -> {:error, :malformed_template}
    end
  end

  defp split_names(bin, count) do
    names = bin |> :binary.split(<<0>>, [:global, :trim_all]) |> Enum.take(count)
    if length(names) == count, do: names, else: :error
  end
end
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mix test test/eipex/cip/logix_test.exs`
Expected: PASS, 13 tests, 0 failures.

- [ ] **Step 5: Run the whole suite and commit**

Run: `mix test`
Expected: PASS, 0 failures across all codec test files.

Append to `CHANGELOG.md`: `- [Added] Logix services codec: tag read/write, RMW, MSP, symbol list, templates`

```bash
mix format && git add -A && git commit -m "feat: Logix tag and template services codec"
```

---

## Completion criteria for Phase 1

- `mix test` green: all eight codec modules covered by byte-vector tests.
- `mix format --check-formatted` passes.
- No runtime dependencies in `mix.exs` (only `stream_data` under `:dev`/`:test`).
- `CHANGELOG.md` has one `[Added]` line per task.

## After this plan

Phases 2–7 of the spec each get their own implementation plan, written after
the previous phase lands (Phase 2: explicit scanner — session GenServer, UCMM,
`generic_message`, `discover`; validated against cpppo). The codecs built here
are consumed unchanged by those phases.

