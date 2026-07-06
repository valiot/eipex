defmodule Eipex.Adapter.LoopbackTest do
  use ExUnit.Case

  alias Eipex.Scanner

  defmodule ConfigGuard do
    use Eipex.Adapter.Handler
    def after_assembly_write(151, <<0xA5, _>>, _ctx), do: :ok
    def after_assembly_write(151, _, _ctx), do: {:error, 0x09}
    def after_assembly_write(_, _, _), do: :ok
  end

  @identity [
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex Adapter"
  ]

  defp start_pair(extra \\ []) do
    {:ok, adapter} =
      Eipex.Adapter.start_link(
        [
          identity: @identity,
          handler: ConfigGuard,
          assemblies: [
            input: [instance: 100, size: 4],
            output: [instance: 150, size: 4],
            config: [instance: 151, size: 2]
          ],
          port: 0,
          io_udp_port: 0
        ] ++ extra
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
               service: 0x0E,
               class: 0x01,
               instance: 1,
               attribute: 1,
               route_path: [backplane: 0]
             )

    Scanner.close(scanner)
  end

  test "CIP errors surface through the scanner helpers" do
    {_adapter, scanner} = start_pair()

    assert {:error, {:cip, :path_destination_unknown, _}} =
             Scanner.get_attribute(scanner, 0x77, 1, 1)

    Scanner.close(scanner)
  end
end
