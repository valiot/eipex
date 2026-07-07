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

## Usage: Logix tags

Example: scanner discovers tags on a Logix controller, reads and writes
typed values:

    {:ok, scanner} = Eipex.Scanner.start_link(
      host: {192, 168, 1, 10}
    )

    # Discover tags and fetch UDT templates
    {:ok, catalog} = Eipex.Scanner.Logix.tag_list(scanner)
    # catalog.tags lists all tags with their types
    # catalog.templates contains UDT definitions for structures

    # Read a single atomic tag
    {:ok, tag} = Eipex.Scanner.Logix.read(scanner, "TotalCount")
    tag.value  # The typed scalar value
    tag.type   # Atom like :dint, :real, :bool, ...
    tag.error  # nil on success

    # Read a structured tag (UDT) into a member map
    {:ok, tag} = Eipex.Scanner.Logix.read(scanner, "Motor", tags: catalog)
    tag.value  # %{"running" => true, "speed" => 100, "amps" => 3.5, ...}

    # Bulk read multiple tags in one or more MSP batches
    {:ok, tags} = Eipex.Scanner.Logix.read(
      scanner,
      ["A", "B", "C"],
      tags: catalog,
      connection_size: 500  # MSP batch threshold (bytes)
    )
    # tags is a list of %Eipex.Tag{} in the same order

    # Write a value, type inferred from catalog or the value
    :ok = Eipex.Scanner.Logix.write(scanner, "CartonSize", 14)

    # Write with an explicit type
    :ok = Eipex.Scanner.Logix.write(scanner, "Flag", true, type: :bool)

    :ok = Eipex.Scanner.close(scanner)

Refer to `Eipex.Scanner.Logix` for detailed documentation on type
resolution, bulk batching, fragmentation, tag/element addressing
(`Tag[i]`, `A.B`), and scope limitations (structure writes and
multi-element array writes unsupported).

## Interop testing

`mix test` is hermetic. To run interop tests against the cpppo Logix simulator:

    docker compose -f interop/docker-compose.yml up -d
    mix test --include interop
    docker compose -f interop/docker-compose.yml down

The same cpppo service also backs the Logix scanner interop (tag read,
write and bulk Multiple Service Packet read):

    mix test --include interop test/interop/cpppo_logix_test.exs

The adapter side is exercised with pycomm3:

    mix test --include interop test/interop/pycomm3_test.exs

The scanner's class 1 I/O is validated against OpENer, the ODVA reference
adapter (builds from source, binds host loopback):

    docker compose -f interop/docker-compose.yml --profile opener up -d --build opener
    mix test --include interop test/interop/opener_test.exs
    docker compose -f interop/docker-compose.yml down
