defmodule Eipex.Interop.OpenerTest do
  @moduledoc """
  Interop against OpENer (the ODVA reference adapter, C).
  Start it first: docker compose -f interop/docker-compose.yml up -d --build opener
  Run with: mix test --include interop test/interop/opener_test.exs
  """

  use ExUnit.Case

  alias Eipex.Scanner

  @moduletag :interop
  @moduletag timeout: 600_000
  @host System.get_env("OPENER_HOST", "127.0.0.1")

  test "identity, explicit assembly access and class 1 I/O against OpENer" do
    {:ok, scanner} = Scanner.start_link(host: @host, vendor_id: 0x004D)

    # OpENer's CMakeLists.txt defaults OpENer_Device_Config_Vendor_Id to 1
    # (not 365 as commonly assumed elsewhere) unless overridden at build time;
    # verified against the source clone this image was built from.
    assert {:ok, <<vendor::16-little>>} = Scanner.get_attribute(scanner, 0x01, 1, 1)
    assert vendor == 1

    # sample app assemblies (src/ports/POSIX/sample_application/sampleapplication.c):
    # input 100 and output 150 are 32 bytes each; config 151 is 10 bytes (its
    # size is irrelevant here since Forward Open never carries a config size).
    {:ok, io} =
      Scanner.open_io(scanner,
        o_to_t: [assembly: 150, size: 32, rpi: 100_000, run_idle: true],
        t_to_o: [assembly: 100, size: 32, rpi: 100_000, run_idle: false],
        config: [assembly: 151],
        timeout_multiplier: 2,
        owner: self()
      )

    assert_receive {:eipex_io, ^io, :data, data}, 5_000
    assert byte_size(data) == 32

    # write output data cyclically, then read assembly 150 back explicitly
    payload = :binary.copy(<<0xA5>>, 32)
    :ok = Eipex.Scanner.IOConnection.set_output(io, payload)
    Process.sleep(500)

    assert {:ok, ^payload} = Scanner.get_attribute(scanner, 0x04, 150, 3)

    :ok = Eipex.Scanner.IOConnection.close(io)
    assert_receive {:eipex_io, ^io, :closed}, 1_000

    Scanner.close(scanner)
  end
end
