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
end
