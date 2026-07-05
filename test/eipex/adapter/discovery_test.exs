defmodule Eipex.Adapter.DiscoveryTest do
  use ExUnit.Case

  @identity [
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex Adapter"
  ]

  defp start_adapter(discovery) do
    {:ok, pid} =
      Eipex.Adapter.start_link(
        identity: @identity,
        assemblies: [],
        port: 0,
        discovery: discovery
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
