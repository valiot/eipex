defmodule Eipex.AdapterTest do
  use ExUnit.Case

  @identity [
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex Adapter"
  ]

  defp start_adapter(extra \\ []) do
    {:ok, pid} =
      Eipex.Adapter.start_link(
        [
          identity: @identity,
          assemblies: [
            input: [instance: 100, size: 4],
            output: [instance: 150, size: 4],
            config: [instance: 151, size: 2]
          ],
          port: 0,
          io_udp_port: 0
        ] ++ extra
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

    assert {:error, {:missing_identity_option, :product_name}} =
             Eipex.Adapter.start_link(
               identity: [vendor_id: 1, product_code: 2],
               assemblies: [],
               port: 0
             )
  end
end
