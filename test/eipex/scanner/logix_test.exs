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
end
