defmodule Eipex.Adapter.Object.NetworkObjectsTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{Config, MessageRouter}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.Identity

  defp config do
    %Config{
      identity: %Identity{
        vendor_id: 0x4D,
        device_type: 0x0C,
        product_code: 0x77,
        revision: {1, 0},
        serial_number: 1,
        product_name: "X"
      },
      handler: Eipex.Adapter.Handler.Default,
      inactivity_timeout: 120_000,
      network: %{
        ip: {192, 168, 1, 10},
        netmask: {255, 255, 255, 0},
        gateway: {192, 168, 1, 1},
        hostname: "eipex",
        mac: <<1, 2, 3, 4, 5, 6>>
      },
      objects: %{
        0x01 => Eipex.Adapter.Object.Identity,
        0x06 => Eipex.Adapter.Object.ConnectionManager,
        0xF5 => Eipex.Adapter.Object.TcpIpInterface,
        0xF6 => Eipex.Adapter.Object.EthernetLink
      }
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
    assert %{data: <<10, 1, 168, 192, 0, 255, 255, 255, 1, 1, 168, 192, 0::32, 0::32, 0::16>>} =
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
