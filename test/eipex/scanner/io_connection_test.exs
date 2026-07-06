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

  test "forward open rejections surface as errors" do
    {_adapter, scanner} = start_pair()

    assert {:error, {:cip, :connection_failure, [0x0127, 10]}} =
             open_io(scanner, o_to_t: [assembly: 150, size: 9, rpi: 20_000, run_idle: true])

    Scanner.close(scanner)
  end

  defp eventually(fun, tries \\ 50) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(20) && eventually(fun, tries - 1)
    end
  end
end
