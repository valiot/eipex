# Eipex Phase 6 — Scanner Logix Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A high-level Logix tag interface on the scanner: `Eipex.Scanner.Logix.tag_list/1` (discover tags via the Symbol Object, fetch and cache UDT templates), `read/2` (one tag or a list — automatic Multiple Service Packet grouping and fragmentation, typed values including structures/arrays/strings), and `write/3` (typed value with the correct type prefix). Validated by loopback against a real-socket Logix responder and by a real cpppo interop run for atomic read/write/bulk.

**Architecture:** Pure scanner-side orchestration over the existing session. All wire I/O goes through `Eipex.Scanner.generic_message/2` (service/path/data → decoded response), which already handles UCMM, route wrapping and connected messaging. The Logix codec (`Eipex.CIP.Logix`) and type codec (`Eipex.CIP.Types`, incl. `decode_typed/1`, `decode_symbol_type/1`) are complete from Phase 1 — the only codec gap is exposing the Multiple Service Packet data body (Task 1). The meaty new logic is the value layer: decoding a Logix read reply into an Elixir term using a template registry (atomic, arrays, structures, Logix STRING), and encoding a term back for writes.

**Scope decisions (documented):**
- Reads/writes run over **UCMM by default** (what cpppo supports); a caller may pass `connected: true` to ride an open class 3 connection (that opt flows straight through `generic_message`). Fragmentation threshold defaults to 500 bytes (UCMM/standard connection), overridable via `connection_size:`.
- **Tag list + templates validated hermetically** against a real-socket Logix responder (test support speaking the real wire format via the real codecs — not a mock), because cpppo does not faithfully emulate a Logix controller's Symbol/Template objects. cpppo validates atomic read/write/bulk interop.
- **BOOL-in-SINT bit unpacking within UDTs and nested-array-of-struct edge cases are decoded best-effort** using template offsets; deeply nested UDTs beyond two levels are deferred (documented).
- No tag-metadata caching process — `tag_list/1` returns a plain map the caller passes back to `read/2` (`tags:` opt) when it wants structure decoding; without it, `read/2` still decodes atomics and reports structs as raw `{:struct, handle, bytes}`.

**Tech Stack:** Elixir/OTP only. cpppo in docker (existing harness) for interop.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. No mocks — loopback uses a real TCP Logix responder (real codecs) and the real scanner.
- Decode-side functions never raise on device data; per-tag failures are returned in the tag result, never crash the batch (pycomm3 semantics).
- `mix format` before every commit. One CHANGELOG line per commit: `[Type] What changed`, ≤100 chars, appended at the bottom.
- TDD: failing test first. Phases 1-5 suites (245 tests + 3 properties, 4 interop excluded) stay green throughout.

## File Structure

```
eipex/
├── lib/eipex/
│   ├── cip/logix.ex                 # Task 1: multiple_service_data/1
│   ├── scanner/logix.ex             # Tasks 3-5: tag_list, read, write orchestration
│   └── scanner/logix/value.ex       # Task 2: pure value decode/encode with template registry
├── test/support/logix_responder.ex  # Task 3: real-TCP Logix target (handler factory)
├── test/eipex/scanner/logix/value_test.exs      # Task 2
├── test/eipex/scanner/logix_test.exs            # Tasks 3-5 (loopback)
└── test/interop/cpppo_logix_test.exs            # Task 6
```

**Public API after this phase:**

```elixir
{:ok, catalog} = Eipex.Scanner.Logix.tag_list(plc)
# catalog :: %{tags: [%Eipex.Scanner.Logix.Tag{}], templates: %{handle => template}}
# %Tag{name, instance, type: atom | {:struct, handle} | {:array, elem_type, dims}, dims, system?}

{:ok, %Eipex.Tag{value: 534, type: :dint, error: nil}} = Eipex.Scanner.Logix.read(plc, "TotalCount")
{:ok, [%Eipex.Tag{}, ...]} = Eipex.Scanner.Logix.read(plc, ["A", "B", "C"], tags: catalog)
:ok = Eipex.Scanner.Logix.write(plc, "CartonSize", 14)               # infers DINT-ish from value + catalog
:ok = Eipex.Scanner.Logix.write(plc, "Flag", true, type: :bool)      # explicit type
```

`%Eipex.Tag{name, value, type, error}` is the per-tag result (already sketched in
the design spec). `error` is `nil` on success or `{:cip, status_name, extended}` /
`:no_template` etc.; `read/2` of a list returns `{:ok, [%Tag{}]}` where individual
tags may carry errors — the call itself only errors on transport failure.

---

### Task 1: Codec — expose Multiple Service Packet data body

**Files:**
- Modify: `lib/eipex/cip/logix.ex`
- Test: `test/eipex/cip/logix_test.exs` (append)

**Interfaces:**
- Produces: `Eipex.CIP.Logix.multiple_service_data([mr_request_binary]) :: binary` — the count + offset table + concatenated sub-requests (everything after the MR service+path). `encode_multiple_service/1` is refactored to `MessageRouter.encode_request(0x0A, [class: 0x02, instance: 1], multiple_service_data(requests))` so both share one implementation. This lets the scanner send an MSP through `generic_message(service: 0x0A, path: [class: 0x02, instance: 1], data: multiple_service_data(subs))`.

- [ ] **Step 1: Write the failing test (append to `test/eipex/cip/logix_test.exs`)**

```elixir
  test "multiple_service_data exposes the packet body used by encode_multiple_service" do
    r1 = Logix.encode_read_tag(symbolic: "AB")
    r2 = Logix.encode_read_tag(symbolic: "CDEF")

    data = Logix.multiple_service_data([r1, r2])
    assert data == <<2::16-little, 6::16-little, (6 + byte_size(r1))::16-little, r1::binary, r2::binary>>

    # encode_multiple_service is exactly this body wrapped in the MR request
    assert Logix.encode_multiple_service([r1, r2]) ==
             Eipex.CIP.MessageRouter.encode_request(0x0A, [class: 0x02, instance: 1], data)
  end
```

- [ ] **Step 2: Run to verify it fails**

Run: `mix test test/eipex/cip/logix_test.exs`
Expected: FAIL — `multiple_service_data/1` undefined.

- [ ] **Step 3: Implement**

Extract the body builder from `encode_multiple_service/1`:

```elixir
  @spec multiple_service_data([binary()]) :: binary()
  def multiple_service_data(requests) do
    count = length(requests)
    first_offset = 2 + count * 2

    {offsets, _} =
      Enum.map_reduce(requests, first_offset, fn req, offset ->
        {<<offset::16-little>>, offset + byte_size(req)}
      end)

    <<count::16-little, IO.iodata_to_binary(offsets)::binary,
      IO.iodata_to_binary(requests)::binary>>
  end

  @spec encode_multiple_service([binary()]) :: binary()
  def encode_multiple_service(requests) do
    MessageRouter.encode_request(0x0A, @message_router_path, multiple_service_data(requests))
  end
```

- [ ] **Step 4: Run to verify it passes**

Run: `mix test test/eipex/cip/logix_test.exs`
Expected: PASS (new test + the existing MSP tests unchanged). Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Expose Multiple Service Packet data body for scanner-side batching`

```bash
mix format && git add -A && git commit -m "feat: expose multiple service packet body"
```

---

### Task 2: Value layer — decode/encode Logix values with a template registry

**Files:**
- Create: `lib/eipex/scanner/logix/value.ex`
- Test: `test/eipex/scanner/logix/value_test.exs`

**Interfaces:**
- Consumes: `Eipex.CIP.Types` (`decode_typed/1`, `decode/2`, `encode/2`, `type_code/1`, `decode_symbol_type/1`).
- Produces (pure functions; `templates :: %{handle => %{name, members, structure_size}}` where each member is `%{name, raw_type, symbol_type, offset, info}` as returned by `Eipex.CIP.Logix.decode_template_definition/2` — the registry adds `structure_size` from the template attributes):
  - `Value.decode_reply(reply_data :: binary, templates) :: {:ok, term} | {:error, reason}` — decodes a Read Tag reply's type-prefixed data. Atomic → the value (or list for arrays). `{:short_string, s}` → the string. Struct marker `<<0xA0, 0x02, handle::16-little, body>>` → `decode_struct(handle, body, templates)`; if `handle` is not in `templates` → `{:ok, {:struct, handle, body}}` (raw passthrough, not an error).
  - `Value.decode_struct(handle, body, templates) :: {:ok, map | String.t} :: ...` — a Logix-STRING-shaped template (exactly two members named `LEN` (DINT) + `DATA` (SINT array), or the predefined STRING layout `DINT len + SINT[n]`) decodes to an Elixir string; otherwise a map `%{member_name => value}` decoding each member at its `offset` (atomic via `Types.decode/2` on the member's byte slice; nested struct member via recursion; BOOL member → bit at `symbol_type.bool_position` of the host byte at `offset`).
  - `Value.encode(value, type, templates) :: {:ok, {type_prefix :: binary, bytes :: binary}} | {:error, reason}` — for a write. Atomic types → `{<<Types.type_code(type)::16-little>>, encoded}`. `:bool` → `{<<0xC1::16-little>>, <<(if value, do: 0xFF, else: 0x00)>>}`. Structures are out of scope for write in this phase → `{:error, :struct_write_unsupported}` (documented).
  - `Value.string?(template) :: boolean` — the Logix-STRING detection helper.

- [ ] **Step 1: Write the failing tests**

`test/eipex/scanner/logix/value_test.exs`:

```elixir
defmodule Eipex.Scanner.Logix.ValueTest do
  use ExUnit.Case, async: true

  alias Eipex.Scanner.Logix.Value

  test "decodes atomic scalar and array replies" do
    assert {:ok, 534} = Value.decode_reply(<<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>, %{})
    assert {:ok, [7, 8]} = Value.decode_reply(<<0xC3, 0x00, 7, 0, 8, 0>>, %{})
    assert {:ok, true} = Value.decode_reply(<<0xC1, 0x00, 0xFF>>, %{})
  end

  test "unknown-handle structs pass through raw, not error" do
    reply = <<0xA0, 0x02, 0xAB, 0x0F, 1, 2, 3, 4>>
    assert {:ok, {:struct, 0x0FAB, <<1, 2, 3, 4>>}} = Value.decode_reply(reply, %{})
  end

  test "decodes a flat struct into a member map at member offsets" do
    # UDT with pilot_on(BOOL@0 bit0), count(INT@2), rate(REAL@4)
    template = %{
      name: "MyUDT",
      structure_size: 8,
      members: [
        %{name: "pilot_on", raw_type: 0x00C1, symbol_type: %{atomic_type: :bool, bool_position: 0, structure?: false}, offset: 0, info: 0},
        %{name: "count", raw_type: 0x00C3, symbol_type: %{atomic_type: :int, structure?: false}, offset: 2, info: 0},
        %{name: "rate", raw_type: 0x00CA, symbol_type: %{atomic_type: :real, structure?: false}, offset: 4, info: 0}
      ]
    }

    # body: byte0 = 0x01 (pilot_on true, bit0), bytes2-3 = INT 300, bytes4-7 = REAL 1.5
    body = <<0x01, 0x00, 300::16-little, 1.5::32-little-float>>
    templates = %{0x1111 => template}

    assert {:ok, %{"pilot_on" => true, "count" => 300, "rate" => 1.5}} =
             Value.decode_reply(<<0xA0, 0x02, 0x11, 0x11, body::binary>>, templates)
  end

  test "decodes a Logix STRING struct to an Elixir string" do
    # predefined STRING: LEN(DINT)@0 + DATA(SINT[82])@4, structure_size 88
    template = %{
      name: "STRING",
      structure_size: 88,
      members: [
        %{name: "LEN", raw_type: 0x00C4, symbol_type: %{atomic_type: :dint, structure?: false}, offset: 0, info: 0},
        %{name: "DATA", raw_type: 0x00C2, symbol_type: %{atomic_type: :sint, structure?: false}, offset: 4, info: 82}
      ]
    }

    text = "hello"
    data = <<byte_size(text)::32-little, text::binary, 0::(82 - byte_size(text))*8>>
    templates = %{0x2222 => template}

    assert {:ok, "hello"} = Value.decode_reply(<<0xA0, 0x02, 0x22, 0x22, data::binary>>, templates)
    assert Value.string?(template)
  end

  test "encodes atomic values for writes" do
    assert {:ok, {<<0xC4, 0x00>>, <<0x0E, 0x00, 0x00, 0x00>>}} = Value.encode(14, :dint, %{})
    assert {:ok, {<<0xC1, 0x00>>, <<0xFF>>}} = Value.encode(true, :bool, %{})
    assert {:ok, {<<0xC1, 0x00>>, <<0x00>>}} = Value.encode(false, :bool, %{})
    assert {:error, :bad_value} = Value.encode(70_000, :int, %{})
    assert {:error, :struct_write_unsupported} = Value.encode(%{}, {:struct, 1}, %{})
  end
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `mix test test/eipex/scanner/logix/value_test.exs`
Expected: FAIL — module undefined.

- [ ] **Step 3: Implement `Eipex.Scanner.Logix.Value`**

Key logic (write the module in full following this shape):

```elixir
defmodule Eipex.Scanner.Logix.Value do
  @moduledoc """
  Decodes Logix read replies into Elixir terms and encodes terms for writes,
  using a UDT template registry (handle => template). Atomic values, arrays,
  member-map structures and Logix STRING structs are supported; structure
  writes are not (this phase).
  """

  alias Eipex.CIP.Types

  @spec decode_reply(binary(), map()) :: {:ok, term()} | {:error, term()}
  def decode_reply(<<0xA0, 0x02, handle::16-little, body::binary>>, templates) do
    case Map.fetch(templates, handle) do
      {:ok, template} -> decode_struct(template, body, templates)
      :error -> {:ok, {:struct, handle, body}}
    end
  end

  def decode_reply(reply_data, _templates) do
    case Types.decode_typed(reply_data) do
      {:ok, {:short_string, s}} -> {:ok, s}
      {:ok, {_type, value}} -> {:ok, value}
      {:error, _} = error -> error
    end
  end

  @spec decode_struct(map(), binary(), map()) :: {:ok, term()} | {:error, term()}
  def decode_struct(template, body, templates) do
    if string?(template) do
      {:ok, decode_string(template, body)}
    else
      decode_members(template.members, body, templates)
    end
  end

  @spec string?(map()) :: boolean()
  def string?(%{members: members}) do
    case members do
      [%{name: len_name} = len, %{name: data_name} = data] ->
        String.upcase(len_name) == "LEN" and String.upcase(data_name) == "DATA" and
          len.symbol_type.atomic_type in [:dint, :int] and
          data.symbol_type.atomic_type == :sint

      _ ->
        false
    end
  end

  def string?(_), do: false

  # decode_string: read LEN at its offset, take that many DATA bytes.
  # decode_members: for each member, slice body at offset, decode by kind
  #   (bool -> bit at bool_position of the byte at offset; atomic -> Types.decode
  #   on the element-sized slice; nested struct -> recurse via its template).
  # encode/3: atomic -> {<<Types.type_code(type)::16-little>>, encoded};
  #   :bool special-cased; {:struct, _} -> {:error, :struct_write_unsupported}.
end
```

Member slicing: an atomic member's byte width is `Eipex.CIP.Types` element size
(sint 1, int 2, dint/real 4, lint/lreal 8); a BOOL member reads one byte at
`offset` and tests `Bitwise.band(byte, 1 <<< bool_position)`; a nested struct
member's byte span runs to the next member's offset (or `structure_size` for the
last). Keep nesting to two levels (document the limit). Return `{:error, reason}`
if a slice runs past the body.

- [ ] **Step 4: Run to verify it passes**

Run: `mix test test/eipex/scanner/logix/value_test.exs`
Expected: PASS, 5 tests. Full `mix test` green.

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Logix value layer: struct/array/string decode and atomic write encode`

```bash
mix format && git add -A && git commit -m "feat: logix value decode/encode"
```

---

### Task 3: `tag_list/1` — Symbol Object iteration + template fetch/cache

**Files:**
- Create: `lib/eipex/scanner/logix.ex` (module + `tag_list/1`), `test/support/logix_responder.ex`
- Test: `test/eipex/scanner/logix_test.exs`

**Interfaces:**
- Consumes: `Eipex.Scanner.generic_message/2`; `Eipex.CIP.Logix.decode_symbol_list/1`, `decode_template_attributes/1`, `decode_template_definition/2`; `Eipex.CIP.Types.decode_symbol_type/1`.
- Produces:
  - `%Eipex.Scanner.Logix.Tag{name, instance, raw_type, type, dims, system?}` struct — `type` is `:dint | :real | ... | {:struct, handle} | {:array, base, dims}`; `system?` true for tags to hide (bit 12 set, name starting `__`, or containing `:`).
  - `Eipex.Scanner.Logix.tag_list(server, opts \\ []) :: {:ok, %{tags: [%Tag{}], templates: %{handle => template}}} | {:error, term}`:
    1. Iterate the Symbol Object: `generic_message(server, service: 0x55, path: <<0x20, 0x6B, 0x25, 0x00, start::16-little>>, data: <<2::16-little, 1::16-little, 2::16-little>>)`; decode with `decode_symbol_list/1`; while the response `status_name == :partial_transfer` (0x06), continue from `last_instance + 1`; stop on `:success`.
    2. Filter system tags out of the returned list (keep them flagged in the struct but exclude from the default; `opts[:include_system]` keeps them).
    3. For each structured tag (`symbol_type.structure?`), fetch its template ONCE per distinct `template_instance`: Get_Attribute_List (`service: 0x03, path: [class: 0x6C, instance: inst], data: attrs`) → `decode_template_attributes/1` gives `%{handle, member_count, definition_size, structure_size}`; then Read Template in a loop (`service: 0x4C, path: [class: 0x6C, instance: inst], data: <<offset::32-little, bytes::16-little>>` where `bytes = definition_size * 4 - 23 - offset`) accumulating fragments while `status_name == :partial_transfer`; `decode_template_definition(acc, member_count)` → merge `structure_size` in; key the registry by `handle`.
    4. Return `%{tags: user_tags, templates: registry}`.
  - `Eipex.TestSupport.LogixResponder.handler(spec) :: (mr_request -> mr_response | :no_reply)` — a ScriptedTarget handler that speaks the Logix subset: it decodes the MR request (`MessageRouter.decode_request`), dispatches by service, and answers using the real codecs from a `spec` (`%{tags: %{name => {type_atom, value}}, symbols: [%{instance, name, raw_type}], templates: %{instance => %{attrs, definition_binary}}}`). Symbol list returns instances in chunks with status 0x06 until the last chunk (0x00). Reused by Tasks 4-5.

- [ ] **Step 1: Write the LogixResponder support module**

`test/support/logix_responder.ex` — a handler factory (real codecs, no mocks; state via a closure or Agent for symbol-list chunking). It must handle: `0x55` (symbol list, chunked with 0x06), `0x03` on class 0x6C (template attrs), `0x4C` on class 0x6C (read template, fragmented with 0x06), `0x4C` symbolic (read tag), `0x4D` symbolic (write tag), `0x0A` (MSP → dispatch each sub-request and concatenate replies via `Eipex.CIP.Logix.decode_multiple_service_reply`'s inverse — build count+offsets+replies). Structure it as a `case service` returning the reply MR binary built with `MessageRouter.encode_response/3`. (Full module written here by the implementer; ~180 lines, mostly a service switch.)

- [ ] **Step 2: Write the failing tag_list tests**

`test/eipex/scanner/logix_test.exs` — start a `ScriptedTarget` with a `LogixResponder.handler` whose spec includes: two atomic tags, one structured tag referencing a template, one system tag (`__internal`), and a symbol list split across two 0x06 chunks:

```elixir
defmodule Eipex.Scanner.LogixTest do
  use ExUnit.Case

  alias Eipex.Scanner
  alias Eipex.Scanner.Logix
  alias Eipex.TestSupport.{LogixResponder, ScriptedTarget}

  # spec: SCADA (DINT), Rate (REAL), Motor (struct template 0x2E9), __hidden (system)
  defp catalog_spec do
    %{
      symbols: [
        %{instance: 1, name: "SCADA", raw_type: 0x00C4},
        %{instance: 2, name: "Rate", raw_type: 0x00CA},
        %{instance: 3, name: "Motor", raw_type: 0x82E9},   # structure, template inst 0x2E9
        %{instance: 0x1004, name: "__hidden", raw_type: 0x1000}  # system bit
      ],
      chunk_size: 2,   # forces a 0x06 continuation after 2 symbols
      templates: %{
        0x2E9 => LogixResponder.udt(handle: 0x0FAB, name: "Motor",
                   members: [{"running", :bool, 0}, {"speed", :int, 2}, {"amps", :real, 4}],
                   structure_size: 8)
      }
    }
  end

  defp start_plc(spec) do
    target = ScriptedTarget.start(LogixResponder.handler(spec))
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)
    plc
  end

  test "tag_list discovers user tags across continuation chunks and hides system tags" do
    plc = start_plc(catalog_spec())

    assert {:ok, %{tags: tags, templates: templates}} = Logix.tag_list(plc)

    names = Enum.map(tags, & &1.name)
    assert "SCADA" in names and "Rate" in names and "Motor" in names
    refute "__hidden" in names

    scada = Enum.find(tags, &(&1.name == "SCADA"))
    assert scada.type == :dint

    motor = Enum.find(tags, &(&1.name == "Motor"))
    assert motor.type == {:struct, 0x0FAB}

    assert %{0x0FAB => %{name: "Motor", members: members}} = templates
    assert Enum.map(members, & &1.name) == ["running", "speed", "amps"]

    Scanner.close(plc)
  end

  test "include_system keeps hidden tags" do
    plc = start_plc(catalog_spec())
    {:ok, %{tags: tags}} = Logix.tag_list(plc, include_system: true)
    assert Enum.any?(tags, &(&1.name == "__hidden" and &1.system?))
    Scanner.close(plc)
  end
end
```

- [ ] **Step 3: Run to verify it fails**

Run: `mix test test/eipex/scanner/logix_test.exs`
Expected: FAIL — `Logix.tag_list/1` undefined.

- [ ] **Step 4: Implement `tag_list/1` + the `%Tag{}` struct**

Iterate the symbol list following `:partial_transfer`; classify each symbol via
`decode_symbol_type/1` into the `%Tag{}` `type` field; collect distinct
`template_instance`s of structured tags and fetch each template once (attrs +
fragmented read-template loop). Return `%{tags, templates}`. Per-request errors
(non-success status on a symbol-list or template fetch) → `{:error, {:cip, name, ext}}`.

- [ ] **Step 5: Run to verify it passes**

Run: `mix test test/eipex/scanner/logix_test.exs`
Expected: PASS, 2 tests. Full `mix test` green.

- [ ] **Step 6: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner Logix tag_list: Symbol Object discovery with UDT template fetch`

```bash
mix format && git add -A && git commit -m "feat: logix tag list and template discovery"
```

---

### Task 4: `read/2` — single + bulk with MSP grouping and fragmentation

**Files:**
- Modify: `lib/eipex/scanner/logix.ex`
- Test: `test/eipex/scanner/logix_test.exs` (append)

**Interfaces:**
- Consumes: `Value.decode_reply/2`; `Eipex.CIP.Logix.encode_read_tag/2`, `encode_read_tag_fragmented/3`, `multiple_service_data/1`, `decode_multiple_service_reply/1`; `Eipex.Scanner.generic_message/2`; `%Eipex.Tag{}`.
- Produces:
  - `Eipex.Scanner.Logix.read(server, name_or_names, opts \\ [])`:
    - Single tag (binary/segment name): `generic_message(server, service: 0x4C, symbolic: name, data: <<elements::16-little>>)`; `elements` from `opts[:elements]` (default 1). On success → `Value.decode_reply(resp.data, templates)` → `%Eipex.Tag{name, value, type, error: nil}`; on `:partial_transfer` (reply too big) → switch to fragmented read loop (`encode_read_tag_fragmented` with byte offset, accumulate `data` — minus the repeated 2-byte type header on fragments after the first — until `:success`), then decode. On CIP error → `%Tag{error: {:cip, name, ext}}`.
    - List of tags: group into batches whose ESTIMATED reply size stays under `connection_size` (default 500; `opts[:connection_size]`); each batch → one MSP (`service: 0x0A, path: [class: 0x02, instance: 1], data: multiple_service_data(sub_reads)`); split the reply with `decode_multiple_service_reply/1`; decode each sub-reply to a `%Tag{}` (a sub-reply with status 0x06 → fall back to an individual fragmented read for that tag). Returns `{:ok, [%Tag{}]}` in input order. A tag whose estimated size alone exceeds the threshold is read individually (fragmented if needed), never in an MSP.
    - `templates` come from `opts[:tags].templates` when provided; absent → `%{}` (atomics decode, structs pass through raw).
  - The call errors (`{:error, reason}`) only on transport/session failure; CIP-level and per-tag issues live in the `%Tag{}` results.

- [ ] **Step 1: Write the failing tests (append; LogixResponder spec gains tag values, a big tag for fragmentation, and MSP support)**

Cover: (1) single atomic read returns the typed value; (2) single struct read returns a member map using the catalog templates; (3) bulk read of several atomics returns them in order via one MSP; (4) a large tag (> threshold) reads via fragmentation and reassembles; (5) a mixed bulk where one tag is unknown returns that tag with an `error` while the others succeed; (6) reading a struct without passing `tags:` returns the raw `{:struct, handle, bytes}` value with `error: nil`. (Use small `connection_size:` in the bulk test to force MSP batching deterministically.)

- [ ] **Step 2-4: fail → implement → pass** (`mix test test/eipex/scanner/logix_test.exs`).

- [ ] **Step 5: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Scanner Logix read: typed values, bulk Multiple Service Packet, auto fragmentation`

```bash
mix format && git add -A && git commit -m "feat: logix tag read"
```

---

### Task 5: `write/3`

**Files:**
- Modify: `lib/eipex/scanner/logix.ex`
- Test: `test/eipex/scanner/logix_test.exs` (append)

**Interfaces:**
- Consumes: `Value.encode/3`; `Eipex.CIP.Logix.encode_write_tag/4`; `generic_message/2`.
- Produces: `Eipex.Scanner.Logix.write(server, name, value, opts \\ []) :: :ok | {:error, term}`:
  - Type resolution: `opts[:type]` if given; else infer from `opts[:tags]` catalog (the tag's `type`); else infer a sensible atomic type from the value (`is_boolean → :bool`, integer in DINT range → :dint, float → :real) — if none fits, `{:error, :unknown_type}`.
  - `Value.encode(value, type, templates)` → `{type_prefix, bytes}`; `encode_write_tag(name_as_symbolic, type_prefix, elements, bytes)` via `generic_message(service: 0x4D, symbolic: name, data: type_prefix <> <<elements::16-little>> <> bytes)`. Success status → `:ok`; CIP error → `{:error, {:cip, name, ext}}` (a type-mismatch shows up as `:general_error` + extended `0x2107`); `:struct_write_unsupported` propagates.

- [ ] **Steps:** tests (write DINT by inference; write BOOL with explicit type; type-mismatch surfaces the CIP error; struct write → `{:error, :struct_write_unsupported}`), fail, implement, pass, commit.

Append to `CHANGELOG.md`: `- [Added] Scanner Logix write with type inference from catalog or value`

```bash
mix format && git add -A && git commit -m "feat: logix tag write"
```

---

### Task 6: cpppo interop for Logix read/write/bulk

**Files:**
- Create: `test/interop/cpppo_logix_test.exs`
- Modify: `README.md` (a line under the interop section)

**Interfaces:** consumes the full Logix scanner layer against the real cpppo simulator (UCMM, atomic tags). REAL RUN MANDATORY.

- [ ] **Step 1: Write the interop test** (tagged `:interop`, `@moduletag timeout: 300_000`). Bring up cpppo with a few typed tags (the compose service already runs `SCADA=INT[1000]`; extend the command or start with `SCADA=DINT[10] Rate=REAL[1] Flag=SINT[1]` — adjust to what cpppo accepts). Test: `Scanner.Logix.write(plc, "SCADA[0]", 42)` then `read(plc, "SCADA[0]")` returns 42; a bulk `read(plc, ["SCADA[0]", "SCADA[1]"])` returns both; a write with a wrong type surfaces a CIP error. Do NOT call `tag_list` against cpppo (its Symbol Object support is not a faithful Logix controller — note this in the report; tag_list is covered hermetically in Task 3).

  Note on tag addressing: cpppo tags may be addressed as `SCADA[0]` (element). `read/2`/`write/3` accept the tag name as given and pass it as the symbolic segment; verify cpppo's element-addressing syntax and adjust the test tag names to what it accepts (document exactly what worked).

- [ ] **Step 2: Run it for real**

```bash
docker compose -f interop/docker-compose.yml up -d
sleep 45
mix test --include interop test/interop/cpppo_logix_test.exs
docker compose -f interop/docker-compose.yml down
```

Expected: green. ADAPT to observed cpppo reality (tag types/addressing/what read returns) and document everything in the report. Confirm hermetic `mix test` still excludes interop.

- [ ] **Step 3: README line + commit**

Append to `CHANGELOG.md`: `- [Added] cpppo interop for Logix read/write/bulk`

```bash
mix format && git add -A && git commit -m "test: cpppo logix interop"
```

---

### Task 7: Docs

**Files:**
- Modify: `lib/eipex/scanner/logix.ex` (moduledoc + `@doc` on `tag_list`/`read`/`write`), `README.md` (Logix usage example)

- [ ] **Step 1:** Moduledoc for `Eipex.Scanner.Logix` explaining the tag interface, the `catalog` → `read(tags:)` flow for structure decoding, the UCMM-vs-connected note, and the scope limits (structure writes unsupported, deep nesting best-effort). `@doc` on the three public functions with the exact result shapes (verify against the code). README gets a Logix example mirroring the header sketch. No behavior changes.

- [ ] **Step 2:** `mix format && mix test` green; `mix compile --warnings-as-errors` clean.

- [ ] **Step 3:** Append to `CHANGELOG.md`: `- [Added] Scanner Logix documentation and usage example`

```bash
git add -A && git commit -m "docs: logix services documentation"
```

---

## Completion criteria for Phase 6

- `mix test` green and hermetic; Phases 1-5 untouched and green.
- Loopback Logix suite green: tag_list (continuation + templates + system filtering), read (single/struct/bulk-MSP/fragmentation/per-tag errors), write (inference/explicit/mismatch/struct-unsupported).
- `mix test --include interop` green for cpppo Logix read/write/bulk (real run, output in the report) — plus the existing cpppo/pycomm3/OpENer suites still green.
- `mix format --check-formatted`; zero runtime deps; one CHANGELOG line per task.

## After this plan

Phase 7 (docs polish across the whole library, an EDS sample, and the hex.pm
release of v0.1.0) closes the stack. The `abex`/libplctag NIF can then be
retired in favor of this pure-Elixir path. Deferred from this phase: structure
writes, deeply nested UDT decode (>2 levels), and tag_list against cpppo.

