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
        # structure, template inst 0x2E9
        %{instance: 3, name: "Motor", raw_type: 0x82E9},
        # system bit
        %{instance: 0x1004, name: "__hidden", raw_type: 0x1000}
      ],
      # forces a 0x06 continuation after 2 symbols
      chunk_size: 2,
      templates: %{
        0x2E9 =>
          LogixResponder.udt(
            handle: 0x0FAB,
            name: "Motor",
            members: [{"running", :bool, 0}, {"speed", :int, 2}, {"amps", :real, 4}],
            structure_size: 8
          )
      }
    }
  end

  defp start_plc(spec) do
    {plc, _target} = start_plc_with_target(spec)
    plc
  end

  defp start_plc_with_target(spec) do
    target = ScriptedTarget.start(LogixResponder.handler(spec))
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)
    {plc, target}
  end

  # catalog_spec's symbols/templates (Motor UDT) plus a value store for read
  # tests: SCADA/Rate/Count atomics, Motor's struct body, and a 120-element
  # SINT array (BigArray) big enough to force fragmentation once
  # `tag_chunk_size` is set.
  defp read_spec do
    catalog_spec()
    |> Map.put(:tag_chunk_size, 30)
    |> Map.put(:tags, %{
      "SCADA" => {:dint, 4321},
      "Rate" => {:real, 12.5},
      "Count" => {:dint, 99},
      "Motor" => {:struct, 0x0FAB, <<1, 0, 44::16-little, 3.5::32-little-float>>},
      "BigArray" => {:sint, Enum.to_list(1..120)}
    })
  end

  # Decodes every SendRRData frame's embedded Message Router request and
  # returns the list of service bytes, oldest first — lets a test assert
  # *how* a read was carried out (one MSP vs. several fragments) and not
  # just its final result.
  defp mr_services(target) do
    for %Eipex.Encap{command: :send_rr_data} = frame <- ScriptedTarget.frames(target) do
      {:ok, cpf} = Eipex.Encap.unwrap_cpf(frame)
      {:ok, items} = Eipex.CPF.decode(cpf)
      [{:unconnected_data, mr_request}] = for {:unconnected_data, _} = i <- items, do: i
      {:ok, %{service: service}} = Eipex.CIP.MessageRouter.decode_request(mr_request)
      service
    end
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

  test "empty partial-transfer symbol list returns an error, not a crash" do
    handler = fn mr ->
      {:ok, %{service: service}} = Eipex.CIP.MessageRouter.decode_request(mr)
      # service 0x55 symbol list: reply status 0x06 (partial) with ZERO symbols
      Eipex.CIP.MessageRouter.encode_response(service, 0x06, data: <<>>)
    end

    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    # Wrap in Task with timeout to catch hangs
    task = Task.async(fn -> Logix.tag_list(plc) end)
    assert {:ok, {:error, :malformed_symbol_list}} = Task.yield(task, 2000)

    Scanner.close(plc)
  end

  test "non-advancing partial-transfer symbol list errors, not an infinite loop" do
    # Always answers with a single symbol at instance 0, status partial_transfer
    # (0x06), no matter what start instance was requested — the second
    # continuation (start=1) then carries a last instance (0) that doesn't
    # advance past the requested start, which must not spin forever.
    handler = fn mr ->
      {:ok, %{service: service}} = Eipex.CIP.MessageRouter.decode_request(mr)
      symbol = <<0::32-little, 3::16-little, "Tag", 0x00C4::16-little>>
      Eipex.CIP.MessageRouter.encode_response(service, 0x06, data: symbol)
    end

    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    # Wrap in Task with timeout to catch hangs
    task = Task.async(fn -> Logix.tag_list(plc) end)
    assert {:ok, {:error, :malformed_symbol_list}} = Task.yield(task, 2000)

    Scanner.close(plc)
  end

  test "empty partial-transfer template chunk returns an error, not a hang" do
    # symbol list: one structured tag (template instance 0x2E9), status success
    symbol = <<0x2E9::32-little, 5::16-little, "Motor", 0x82E9::16-little>>

    handler = fn mr ->
      {:ok, %{service: service}} = Eipex.CIP.MessageRouter.decode_request(mr)

      cond do
        service == 0x55 ->
          Eipex.CIP.MessageRouter.encode_response(0x55, 0x00, data: symbol)

        service == 0x03 ->
          # template attrs: definition_size big enough to require a read; member_count 1
          data =
            <<4::16-little, 4::16-little, 0::16-little, 0x40::32-little, 5::16-little,
              0::16-little, 0x08::32-little, 2::16-little, 0::16-little, 1::16-little,
              1::16-little, 0::16-little, 0x0FAB::16-little>>

          Eipex.CIP.MessageRouter.encode_response(0x03, 0x00, data: data)

        service == 0x4C ->
          # read template: partial-transfer with an EMPTY chunk (the hang trigger)
          Eipex.CIP.MessageRouter.encode_response(0x4C, 0x06, data: <<>>)

        true ->
          Eipex.CIP.MessageRouter.encode_response(service, 0x08)
      end
    end

    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    # Wrap in Task with timeout to catch hangs
    task = Task.async(fn -> Logix.tag_list(plc) end)
    assert {:ok, {:error, :malformed_template}} = Task.yield(task, 2000)

    Scanner.close(plc)
  end

  test "template attrs reply short of the four requested attributes errors, not a crash" do
    # symbol list: one structured tag (template instance 0x2E9), status success
    symbol = <<0x2E9::32-little, 5::16-little, "Motor", 0x82E9::16-little>>

    handler = fn mr ->
      {:ok, %{service: service}} = Eipex.CIP.MessageRouter.decode_request(mr)

      cond do
        service == 0x55 ->
          Eipex.CIP.MessageRouter.encode_response(0x55, 0x00, data: symbol)

        service == 0x03 ->
          # template attrs: only 1 of the 4 requested attributes came back
          # (a device covering fewer attributes than asked) — decode_template_attributes
          # returns a partial map missing :definition_size/:structure_size/:member_count.
          data = <<1::16-little, 1::16-little, 0::16-little, 0x0FAB::16-little>>
          Eipex.CIP.MessageRouter.encode_response(0x03, 0x00, data: data)

        true ->
          Eipex.CIP.MessageRouter.encode_response(service, 0x08)
      end
    end

    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    # Wrap in Task with timeout to catch hangs/crashes
    task = Task.async(fn -> Logix.tag_list(plc) end)
    assert {:ok, {:error, :malformed_template}} = Task.yield(task, 2000)

    Scanner.close(plc)
  end

  test "read/2 returns the typed value for a single atomic tag" do
    plc = start_plc(read_spec())

    assert {:ok, %Eipex.Tag{name: "SCADA", value: 4321, type: :dint, error: nil}} =
             Logix.read(plc, "SCADA")

    Scanner.close(plc)
  end

  test "read/2 decodes a struct tag into a member map using catalog templates" do
    plc = start_plc(read_spec())
    {:ok, catalog} = Logix.tag_list(plc)

    assert {:ok, %Eipex.Tag{name: "Motor", type: {:struct, 0x0FAB}, error: nil, value: value}} =
             Logix.read(plc, "Motor", tags: catalog)

    assert value == %{"running" => true, "speed" => 44, "amps" => 3.5}

    Scanner.close(plc)
  end

  test "read/2 bulk reads several atomics in order via one Multiple Service Packet" do
    {plc, target} = start_plc_with_target(read_spec())

    assert {:ok, [scada, rate, count]} =
             Logix.read(plc, ["SCADA", "Rate", "Count"], connection_size: 200)

    assert %Eipex.Tag{name: "SCADA", value: 4321, error: nil} = scada
    assert %Eipex.Tag{name: "Rate", value: 12.5, error: nil} = rate
    assert %Eipex.Tag{name: "Count", value: 99, error: nil} = count

    # exactly one Multiple Service Packet round trip, not three plain reads
    assert mr_services(target) == [0x0A]

    Scanner.close(plc)
  end

  test "read/2 fragments a tag larger than the size threshold and reassembles it" do
    {plc, target} = start_plc_with_target(read_spec())

    assert {:ok, %Eipex.Tag{name: "BigArray", value: values, type: :sint, error: nil}} =
             Logix.read(plc, "BigArray", elements: 120)

    assert values == Enum.to_list(1..120)

    # the first Read Tag (0x4C) plus at least one Read Tag Fragmented (0x52)
    # continuation — proves the value came back over several messages
    assert [0x4C | rest] = mr_services(target)
    assert rest != [] and Enum.all?(rest, &(&1 == 0x52))

    Scanner.close(plc)
  end

  test "read/2 mixed bulk keeps an unknown tag's error without failing the batch" do
    plc = start_plc(read_spec())

    assert {:ok, [scada, missing, rate]} = Logix.read(plc, ["SCADA", "Missing", "Rate"])

    assert %Eipex.Tag{name: "SCADA", value: 4321, error: nil} = scada
    assert %Eipex.Tag{name: "Rate", value: 12.5, error: nil} = rate

    assert %Eipex.Tag{name: "Missing", value: nil, error: {:cip, :object_does_not_exist, _}} =
             missing

    Scanner.close(plc)
  end

  test "read/2 returns the raw struct passthrough when no tags catalog is given" do
    plc = start_plc(read_spec())

    assert {:ok, %Eipex.Tag{name: "Motor", type: {:struct, 0x0FAB}, error: nil, value: value}} =
             Logix.read(plc, "Motor")

    assert value == {:struct, 0x0FAB, <<1, 0, 44::16-little, 3.5::32-little-float>>}

    Scanner.close(plc)
  end

  test "a degenerate empty partial-transfer read reply returns a tag error, not a hang" do
    # Read Tag replies :partial_transfer (0x06) with just the repeated type
    # header and zero new payload bytes, every time — no progress possible.
    handler = fn mr ->
      {:ok, %{service: service}} = Eipex.CIP.MessageRouter.decode_request(mr)

      case service do
        service when service in [0x4C, 0x52] ->
          Eipex.CIP.MessageRouter.encode_response(service, 0x06, data: <<0xC4, 0x00>>)

        _ ->
          Eipex.CIP.MessageRouter.encode_response(service, 0x08)
      end
    end

    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    # Wrap in Task with timeout to catch hangs
    task = Task.async(fn -> Logix.read(plc, "Stuck") end)

    assert {:ok, {:ok, %Eipex.Tag{name: "Stuck", value: nil, error: :malformed_fragment_reply}}} =
             Task.yield(task, 2000)

    Scanner.close(plc)
  end

  # -- MSP framing overhead accounting + too-large fallback --------------------

  # Mimics a real controller: an MSP reply is only accepted if its actual
  # encoded size (Multiple Service Packet envelope: 2-byte count + one
  # 2-byte offset per sub-reply + each sub-reply's own 4-byte MR header +
  # data) fits under `connection_size`; otherwise the whole request comes
  # back with outer status 0x11 (reply_data_too_large), exactly as a PLC
  # would refuse an over-budget Multiple Service Packet.
  defp dint_reply(value),
    do: <<Eipex.CIP.Types.type_code(:dint)::16-little, value::32-little-signed>>

  defp tag_name_from_path(path) do
    {:ok, segments} = Eipex.CIP.Path.decode(path)
    Keyword.fetch!(segments, :symbolic)
  end

  defp size_capped_msp_handler(values, connection_size) do
    fn mr_request ->
      {:ok, %{service: service, path: path, data: data}} =
        Eipex.CIP.MessageRouter.decode_request(mr_request)

      case service do
        0x4C ->
          value = Map.fetch!(values, tag_name_from_path(path))
          Eipex.CIP.MessageRouter.encode_response(0x4C, 0x00, data: dint_reply(value))

        0x0A ->
          {:ok, requests} = Eipex.CIP.Logix.decode_multiple_service_reply(data)

          replies =
            for request <- requests do
              {:ok, %{path: sub_path}} = Eipex.CIP.MessageRouter.decode_request(request)
              value = Map.fetch!(values, tag_name_from_path(sub_path))
              Eipex.CIP.MessageRouter.encode_response(0x4C, 0x00, data: dint_reply(value))
            end

          reply_data = Eipex.CIP.Logix.multiple_service_data(replies)

          if byte_size(reply_data) > connection_size do
            Eipex.CIP.MessageRouter.encode_response(0x0A, 0x11)
          else
            Eipex.CIP.MessageRouter.encode_response(0x0A, 0x00, data: reply_data)
          end
      end
    end
  end

  test "read/2 bulk read accounts for MSP framing overhead when sizing batches" do
    names = for n <- 1..10, do: "T#{n}"
    values = for n <- 1..10, into: %{}, do: {"T#{n}", n * 111}

    # Ten tiny DINT tags: their raw data (6 bytes each) sums to 60, well
    # under 100 either way. But the real MSP envelope also carries a 2-byte
    # offset entry and a 4-byte MR reply header per sub-reply (12 bytes each
    # total), so the true reply for all ten is 122 bytes — over the 100-byte
    # connection_size. An estimate that ignores that framing overhead packs
    # every tag into a single oversized MSP, which this handler (correctly
    # modeling a real controller) refuses outright; an estimate that
    # accounts for it splits the tags across multiple batches that each fit.
    handler = size_capped_msp_handler(values, 100)
    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    assert {:ok, results} = Logix.read(plc, names, connection_size: 100)

    assert Enum.map(results, & &1.name) == names
    assert Enum.map(results, & &1.error) == List.duplicate(nil, 10)
    assert Enum.map(results, & &1.value) == Enum.map(names, &Map.fetch!(values, &1))

    Scanner.close(plc)
  end

  test "read/2 falls back to individual reads when the whole MSP is refused as too large" do
    values = %{"A" => 10, "B" => 20, "C" => 30}

    handler = fn mr_request ->
      {:ok, %{service: service, path: path}} = Eipex.CIP.MessageRouter.decode_request(mr_request)

      case service do
        0x0A ->
          Eipex.CIP.MessageRouter.encode_response(0x0A, 0x11)

        0x4C ->
          value = Map.fetch!(values, tag_name_from_path(path))
          Eipex.CIP.MessageRouter.encode_response(0x4C, 0x00, data: dint_reply(value))
      end
    end

    target = ScriptedTarget.start(handler)
    {:ok, plc} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    assert {:ok, [a, b, c]} = Logix.read(plc, ["A", "B", "C"], connection_size: 200)

    assert %Eipex.Tag{name: "A", value: 10, error: nil} = a
    assert %Eipex.Tag{name: "B", value: 20, error: nil} = b
    assert %Eipex.Tag{name: "C", value: 30, error: nil} = c

    Scanner.close(plc)
  end

  # -- Tag write -----------------------------------------------------------------

  defp write_spec do
    catalog_spec()
    |> Map.put(:tags, %{
      "Counter" => {:dint, 0},
      "Flag" => {:bool, false}
    })
  end

  test "write/3 writes a DINT by type inference and returns :ok" do
    {plc, _target} = start_plc_with_target(write_spec())

    assert :ok = Logix.write(plc, "Counter", 42)

    # Verify via read-back
    assert {:ok, %Eipex.Tag{name: "Counter", value: 42, error: nil}} =
             Logix.read(plc, "Counter")

    Scanner.close(plc)
  end

  test "write/3 writes a BOOL with explicit type and returns :ok" do
    {plc, _target} = start_plc_with_target(write_spec())

    assert :ok = Logix.write(plc, "Flag", true, type: :bool)

    # Verify via read-back
    assert {:ok, %Eipex.Tag{name: "Flag", value: true, error: nil}} =
             Logix.read(plc, "Flag")

    Scanner.close(plc)
  end

  test "write/3 returns error on type mismatch" do
    {plc, _target} = start_plc_with_target(write_spec())

    # Try to write 42 as a bool (type mismatch)
    assert {:error, {:cip, :general_error, [0x2107]}} =
             Logix.write(plc, "Flag", 42)

    Scanner.close(plc)
  end

  test "write/3 returns struct_write_unsupported error for structured tags" do
    {plc, _target} = start_plc_with_target(write_spec())

    assert {:error, :struct_write_unsupported} =
             Logix.write(plc, "Motor", %{"running" => true})

    Scanner.close(plc)
  end

  test "write/3 infers type from catalog when provided" do
    {plc, _target} = start_plc_with_target(write_spec())
    {:ok, catalog} = Logix.tag_list(plc)

    assert :ok = Logix.write(plc, "Counter", 99, tags: catalog)

    # Verify via read-back
    assert {:ok, %Eipex.Tag{name: "Counter", value: 99, error: nil}} =
             Logix.read(plc, "Counter")

    Scanner.close(plc)
  end

  test "explicit unsupported type returns an error, not a crash" do
    {plc, _target} = start_plc_with_target(write_spec())

    assert {:error, :unsupported_type} =
             Logix.write(plc, "Counter", [1, 2, 3], type: {:array, :dint, 1})

    Scanner.close(plc)
  end

  test "catalog struct tag write reports struct_write_unsupported (same as no-catalog)" do
    plc = start_plc(catalog_spec())
    {:ok, catalog} = Logix.tag_list(plc)

    assert {:error, :struct_write_unsupported} =
             Logix.write(plc, "Motor", %{"running" => true}, tags: catalog)

    Scanner.close(plc)
  end

  test "out-of-range float inference errors instead of writing infinity" do
    {plc, _target} = start_plc_with_target(read_spec())

    assert {:error, :unknown_type} = Logix.write(plc, "Rate", 3.5e38)

    Scanner.close(plc)
  end
end
