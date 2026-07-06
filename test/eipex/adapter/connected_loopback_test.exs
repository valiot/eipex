defmodule Eipex.Adapter.ConnectedLoopbackTest do
  use ExUnit.Case

  alias Eipex.Scanner

  @identity [
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex Adapter"
  ]

  defp start_pair(adapter_extra \\ [], scanner_extra \\ []) do
    {:ok, adapter} =
      Eipex.Adapter.start_link(
        [
          identity: @identity,
          assemblies: [output: [instance: 150, size: 4]],
          port: 0
        ] ++ adapter_extra
      )

    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner} =
      Scanner.start_link(
        [host: {127, 0, 0, 1}, port: port, vendor_id: 0x004D, serial_number: 0xDEAD_0001] ++
          scanner_extra
      )

    {adapter, scanner}
  end

  test "full connected round trip: open, request, request, close, reopen" do
    {_adapter, scanner} = start_pair()

    assert {:ok, conn} = Scanner.forward_open(scanner)
    assert conn.variant == :large

    assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
             Scanner.generic_message(scanner,
               service: 0x0E,
               class: 1,
               instance: 1,
               attribute: 1,
               connected: true
             )

    assert :ok =
             Scanner.set_attribute(scanner, 0x04, 150, 3, <<7, 7, 7, 7>>, connected: true)

    assert {:ok, <<7, 7, 7, 7>>} =
             Scanner.get_attribute(scanner, 0x04, 150, 3, connected: true)

    assert :ok = Scanner.forward_close(scanner)

    assert {:error, :no_connection} =
             Scanner.generic_message(scanner,
               service: 0x0E,
               class: 1,
               instance: 1,
               attribute: 1,
               connected: true
             )

    assert {:ok, _} = Scanner.forward_open(scanner)
    Scanner.close(scanner)
  end

  test "duplicate triads across sessions are rejected" do
    {adapter, scanner1} = start_pair()
    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner2} =
      Scanner.start_link(
        host: {127, 0, 0, 1},
        port: port,
        vendor_id: 0x004D,
        serial_number: 0xDEAD_0001
      )

    {:ok, _} = Scanner.forward_open(scanner1)

    # same vendor/serial and both serial counters start at 1 -> same triad;
    # the large attempt AND its standard fallback both collide
    assert {:error, {:cip, :connection_failure, [0x0100]}} =
             Scanner.forward_open(scanner2, variant: :standard)

    Scanner.close(scanner1)
    Scanner.close(scanner2)
  end

  test "closing the session releases connections in the adapter" do
    {adapter, scanner1} = start_pair()
    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, _} = Scanner.forward_open(scanner1)
    Scanner.close(scanner1)
    Process.sleep(100)

    {:ok, scanner2} =
      Scanner.start_link(
        host: {127, 0, 0, 1},
        port: port,
        vendor_id: 0x004D,
        serial_number: 0xDEAD_0001
      )

    # same triad now free again
    assert {:ok, _} = Scanner.forward_open(scanner2, variant: :standard)
    Scanner.close(scanner2)
  end

  test "capacity is enforced" do
    {adapter, scanner1} = start_pair(max_connections: 1)
    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner2} =
      Scanner.start_link(
        host: {127, 0, 0, 1},
        port: port,
        vendor_id: 0x004D,
        serial_number: 0xBEEF_0002
      )

    {:ok, _} = Scanner.forward_open(scanner1)

    assert {:error, {:cip, :connection_failure, [0x0113]}} =
             Scanner.forward_open(scanner2, variant: :standard)

    Scanner.close(scanner1)
    Scanner.close(scanner2)
  end

  test "class 1 forward opens are refused with 0x0103 until phase 5" do
    {_adapter, scanner} = start_pair()

    fo = %Eipex.CIP.ConnectionManager.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: 0x0BAD_CAFE,
      connection_serial: 99,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      timeout_multiplier: 1,
      o2t_rpi: 10_000,
      o2t_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :fixed,
        size: 4
      },
      t2o_rpi: 10_000,
      t2o_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :fixed,
        size: 4
      },
      transport: %{direction: :server, trigger: :cyclic, class: 1},
      connection_path: Eipex.CIP.Path.encode(class: 0x02, instance: 0x01)
    }

    request = Eipex.CIP.ConnectionManager.encode_forward_open(fo, :standard)

    {:ok, %{service: 0x54, path: path, data: data}} =
      Eipex.CIP.MessageRouter.decode_request(request)

    {:ok, [class: class, instance: instance]} = Eipex.CIP.Path.decode(path)

    assert {:ok, %{status_name: :connection_failure, extended: [0x0103]}} =
             Scanner.generic_message(scanner,
               service: 0x54,
               class: class,
               instance: instance,
               data: data
             )

    Scanner.close(scanner)
  end
end
