defmodule Eipex.Scanner.IOConnectionTest do
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

  defp start_pair(adapter_extra \\ []) do
    {:ok, adapter} =
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
        ] ++ adapter_extra
      )

    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner} =
      Scanner.start_link(
        host: {127, 0, 0, 1},
        port: port,
        vendor_id: 0x004D,
        serial_number: 0xDEAD_0001
      )

    {adapter, scanner}
  end

  defp open_io(scanner, extra \\ []) do
    Scanner.open_io(
      scanner,
      [
        o_to_t: [assembly: 150, size: 4, rpi: 20_000, run_idle: true],
        t_to_o: [assembly: 100, size: 4, rpi: 20_000, run_idle: false],
        config: [assembly: 151],
        timeout_multiplier: 0,
        owner: self()
      ] ++ extra
    )
  end

  test "opens, consumes produced data, pushes output, closes" do
    {adapter, scanner} = start_pair()

    :ok = Eipex.Adapter.write_assembly(adapter, 100, <<1, 1, 2, 3>>)
    assert {:ok, io} = open_io(scanner)

    assert_receive {:eipex_io, ^io, :data, <<1, 1, 2, 3>>}, 1_000

    :ok = Eipex.Scanner.IOConnection.set_output(io, <<4, 3, 2, 1>>)

    assert eventually(fn ->
             Eipex.Adapter.read_assembly(adapter, 150) == {:ok, <<4, 3, 2, 1>>}
           end)

    assert :ok = Eipex.Scanner.IOConnection.close(io)
    assert_receive {:eipex_io, ^io, :closed}, 500
    refute Process.alive?(io)

    Scanner.close(scanner)
  end

  test "data change notifications dedup identical payloads" do
    {adapter, scanner} = start_pair()
    {:ok, io} = open_io(scanner)

    assert_receive {:eipex_io, ^io, :data, <<0, 0, 0, 0>>}, 1_000
    refute_receive {:eipex_io, ^io, :data, <<0, 0, 0, 0>>}, 200

    :ok = Eipex.Adapter.write_assembly(adapter, 100, <<5, 5, 5, 5>>)
    assert_receive {:eipex_io, ^io, :data, <<5, 5, 5, 5>>}, 1_000

    Eipex.Scanner.IOConnection.close(io)
    Scanner.close(scanner)
  end

  test "set_output validates size" do
    {_adapter, scanner} = start_pair()
    {:ok, io} = open_io(scanner)

    assert {:error, :size_mismatch} = Eipex.Scanner.IOConnection.set_output(io, <<1>>)

    Eipex.Scanner.IOConnection.close(io)
    Scanner.close(scanner)
  end

  test "consumes t2o multicast production" do
    group = {239, 192, 77, 2}

    {adapter, scanner} =
      start_pair(io: [multicast: [group: group, interface: {127, 0, 0, 1}, ttl: 1]])

    :ok = Eipex.Adapter.write_assembly(adapter, 100, <<7, 7, 7, 7>>)

    assert {:ok, io} =
             open_io(scanner,
               t_to_o: [
                 assembly: 100,
                 size: 4,
                 rpi: 20_000,
                 run_idle: false,
                 type: :multicast,
                 interface: {127, 0, 0, 1}
               ]
             )

    # an independent observer in the group proves production is multicast,
    # not a point-to-point fallback; binding the group address keeps it from
    # intercepting any unicast traffic on the shared port
    {:ok, io_port} = Eipex.Adapter.io_udp_port(adapter)

    {:ok, observer} =
      :gen_udp.open(io_port, [
        :binary,
        active: true,
        reuseaddr: true,
        ip: group,
        add_membership: {group, {127, 0, 0, 1}}
      ])

    assert_receive {:udp, ^observer, _ip, _port, datagram}, 1_000
    assert {:ok, %{data: <<7, 7, 7, 7>>}} = Eipex.IO.decode_packet(datagram, false)

    # the scanner consumed the same group
    assert_receive {:eipex_io, ^io, :data, <<7, 7, 7, 7>>}, 1_000

    # o2t output still flows point-to-point
    :ok = Eipex.Scanner.IOConnection.set_output(io, <<4, 3, 2, 1>>)

    assert eventually(fn ->
             Eipex.Adapter.read_assembly(adapter, 150) == {:ok, <<4, 3, 2, 1>>}
           end)

    :gen_udp.close(observer)
    assert :ok = Eipex.Scanner.IOConnection.close(io)
    Scanner.close(scanner)
  end

  test "a target announcing no usable multicast group yields an error and releases the connection" do
    # a non-multicast "group" makes the adapter's sockaddr_t2o unusable
    {_adapter, scanner} =
      start_pair(io: [multicast: [group: {192, 168, 50, 1}, interface: {127, 0, 0, 1}, ttl: 1]])

    t2o = [assembly: 100, size: 4, rpi: 20_000, run_idle: false, type: :multicast]
    assert {:error, :no_multicast_sockaddr} = open_io(scanner, t_to_o: t2o)

    # the failed attempt must have forward-closed on the target: a second
    # open of the same assembly pair would hit the exclusive-owner conflict
    # (0x0106) if the connection had leaked
    assert {:ok, io} = open_io(scanner)
    Eipex.Scanner.IOConnection.close(io)
    Scanner.close(scanner)
  end

  test "o2t multicast is not supported" do
    {_adapter, scanner} = start_pair()

    assert {:error, :o2t_multicast_unsupported} =
             open_io(scanner,
               o_to_t: [assembly: 150, size: 4, rpi: 20_000, run_idle: true, type: :multicast]
             )

    Scanner.close(scanner)
  end

  test "forward open rejections surface as errors" do
    {_adapter, scanner} = start_pair()

    assert {:error, {:cip, :connection_failure, [0x0127, 10]}} =
             open_io(scanner, o_to_t: [assembly: 150, size: 9, rpi: 20_000, run_idle: true])

    Scanner.close(scanner)
  end

  test "close after the scanner has died stops the io connection cleanly" do
    {_adapter, scanner} = start_pair()
    {:ok, io} = open_io(scanner)
    ref = Process.monitor(io)

    # trap exits to prevent the scanner's death from crashing the test
    old_trap = Process.flag(:trap_exit, true)

    # kill the scanner out from under the io connection (simulates TCP loss teardown)
    Process.exit(scanner, :kill)
    Process.sleep(50)

    # close/1 must not raise even though the forward close cannot be sent
    assert :ok = Eipex.Scanner.IOConnection.close(io)
    assert_receive {:DOWN, ^ref, :process, ^io, _reason}, 1_000

    Process.flag(:trap_exit, old_trap)
  end

  test "watchdog timeout with a dead scanner still notifies the owner and stops" do
    {adapter, scanner} = start_pair()

    {:ok, io} =
      Scanner.open_io(scanner,
        o_to_t: [assembly: 150, size: 4, rpi: 20_000, run_idle: true],
        t_to_o: [assembly: 100, size: 4, rpi: 20_000, run_idle: false],
        config: [assembly: 151],
        timeout_multiplier: 0,
        owner: self()
      )

    ref = Process.monitor(io)

    # trap exits to prevent the scanner's death from crashing the test
    old_trap = Process.flag(:trap_exit, true)

    # kill both scanner and adapter to stop data production
    Process.exit(scanner, :kill)
    Process.exit(adapter, :kill)

    # drain exit messages
    receive do
      {:EXIT, _, :killed} -> :ok
    after
      100 -> :ok
    end

    # the T->O watchdog fires with no producer;
    # the io connection must notify :timeout and stop normally, not crash
    assert_receive {:eipex_io, ^io, :timeout}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^io, :normal}, 1_000

    Process.flag(:trap_exit, old_trap)
  end

  defp eventually(fun, tries \\ 50) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(20) && eventually(fun, tries - 1)
    end
  end
end
