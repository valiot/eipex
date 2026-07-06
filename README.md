# Eipex

EtherNet/IP (CIP) protocol stack in pure Elixir: scanner (originator) and
adapter (target) roles, explicit and implicit messaging, and Logix tag
services. Design: `docs/superpowers/specs/2026-07-02-ethernet-ip-stack-design.md`.

## Usage: Class 1 implicit I/O

Example: scanner opens a cyclic I/O connection to the target, receives input
data, and sends output:

    {:ok, scanner} = Eipex.Scanner.start_link(
      host: {192, 168, 1, 10},
      vendor_id: 0x004D,
      serial_number: 0x1234_5678
    )

    {:ok, io} = Eipex.Scanner.open_io(scanner,
      o_to_t: [assembly: 100, size: 4, rpi: 10_000],
      t_to_o: [assembly: 101, size: 4, rpi: 10_000],
      owner: self()
    )

    # Receive notifications in a loop
    receive do
      {:eipex_io, ^io, :data, input_data} ->
        IO.inspect(input_data, label: "Received from target")
        # Send output back
        :ok = Eipex.Scanner.IOConnection.set_output(io, <<1, 2, 3, 4>>)

      {:eipex_io, ^io, :run_idle, mode} ->
        IO.inspect(mode, label: "Target state")

      {:eipex_io, ^io, :timeout} ->
        IO.puts("Watchdog expired")

      {:eipex_io, ^io, :closed} ->
        IO.puts("I/O connection closed")
    end

    # Close the connection and stop the process
    :ok = Eipex.Scanner.IOConnection.close(io)

## Interop testing

`mix test` is hermetic. To run interop tests against the cpppo Logix simulator:

    docker compose -f interop/docker-compose.yml up -d
    mix test --include interop
    docker compose -f interop/docker-compose.yml down

The adapter side is exercised with pycomm3:

    mix test --include interop test/interop/pycomm3_test.exs

The scanner's class 1 I/O is validated against OpENer, the ODVA reference
adapter (builds from source, binds host loopback):

    docker compose -f interop/docker-compose.yml --profile opener up -d --build opener
    mix test --include interop test/interop/opener_test.exs
    docker compose -f interop/docker-compose.yml down
