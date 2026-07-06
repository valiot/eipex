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
end
