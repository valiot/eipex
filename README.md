# Eipex

A pure-Elixir EtherNet/IP (CIP) protocol stack: scanner (originator) and
adapter (target) roles, explicit and implicit (class 1 I/O) messaging, and
Rockwell Logix tag services. Zero runtime dependencies — built entirely on
OTP's `gen_tcp`, `gen_udp` and `gen_statem`. Full API reference: once
published, see [HexDocs](https://hexdocs.pm/eipex).

## Installation

Add `eipex` to your `mix.exs` dependencies:

    def deps do
      [
        {:eipex, "~> 0.1.0"}
      ]
    end

## Features

| Capability | Scanner (originator) | Adapter (target) |
| --- | --- | --- |
| Discovery (UDP ListIdentity) | ✓ | ✓ |
| Explicit messaging (UCMM) | ✓ | ✓ |
| Connected explicit (class 3) | ✓ | ✓ |
| Class 1 I/O | ✓ | ✓ ¹ |
| Logix tags (read/write, UDTs) | ✓ | n/a ² |

¹ Exclusive-owner, point-to-point connections only — multicast and
input-only/listen-only heartbeat connections are deferred (see
[Known limitations](#known-limitations)).
² The adapter is a generic CIP target, not a Logix PLC — it does not
emulate the Symbol/Template objects Logix tags are built on.

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

## Usage: Adapter

Example: an adapter with an identity, three assemblies (input/output/config)
and a handler that validates configuration writes:

    defmodule MyApp.Handler do
      use Eipex.Adapter.Handler

      def after_assembly_write(151, <<0xA5, _rest::binary>>, _ctx), do: :ok
      def after_assembly_write(151, _data, _ctx), do: {:error, 0x09}
      def after_assembly_write(_instance, _data, _ctx), do: :ok
    end

    {:ok, adapter} = Eipex.Adapter.start_link(
      identity: [
        vendor_id: 0xFFFF,
        product_code: 1,
        product_name: "Eipex Sample Adapter"
      ],
      assemblies: [
        input:  [instance: 100, size: 32],
        output: [instance: 150, size: 32],
        config: [instance: 151, size: 1]
      ],
      handler: MyApp.Handler,
      port: 44_818,
      io_udp_port: 2222
    )

    # Push fresh sensor data into the produced (input) assembly
    :ok = Eipex.Adapter.write_assembly(adapter, 100, <<1, 2, 3, 4>> <> :binary.copy(<<0>>, 28))

    # Read the most recently received (output) assembly data
    {:ok, commanded} = Eipex.Adapter.read_assembly(adapter, 150)

Scanners connect over TCP for explicit messaging (`port`, default 44818) and
open class 1 I/O connections over UDP (`io_udp_port`, default 2222); both
are resolved at runtime via `Eipex.Adapter.port/1` and
`Eipex.Adapter.io_udp_port/1` (handy when starting with `port: 0` in tests).
Implement `Eipex.Adapter.Handler` to validate configuration writes, refresh
input data before a read, or react to run/idle and connection events —
unimplemented callbacks fall through to permissive defaults. See
`Eipex.Adapter` for the full option list (`network`, `discovery`,
`max_connections`, `inactivity_timeout`, `objects`).

A sample EDS matching this exact configuration ships with the package — see
[EDS](#eds) below.

## Known limitations

v0.1.0 ships with the following protocol scope deferred — documented here
rather than silently missing:

- **Multicast** class 1 I/O — only point-to-point O→T/T→O connections are
  accepted; a multicast request is refused (CIP error 0x01, extended
  0x0123/0x0124).
- **Input-only / listen-only** heartbeat connection points — the adapter
  only opens exclusive-owner class 1 connections.
- **Structure (UDT) writes** — `Eipex.Scanner.Logix.write/4` rejects struct
  values (`:struct_write_unsupported`); only atomic scalar writes, and
  single-element writes to array tags, are supported.
- **UDT nesting beyond two levels** — deeper structures decode best-effort
  from template offsets, without a real-controller-verified guarantee.
- **Bit-level and multi-dimension (beyond 2) tag addressing** — bit access
  via a trailing index (e.g. `"Flags.3"`) and indices past two array
  dimensions parse into the expected EPATH segments but are unconfirmed
  against a real controller.

## Interoperability

Verified against three independent EtherNet/IP implementations:

- **[cpppo](https://github.com/pjkundert/cpppo)** — a Logix simulator;
  backs the scanner's explicit messaging and Logix tag (read/write/bulk
  MSP) interop.
- **[pycomm3](https://github.com/ottowayi/pycomm3)** — a Python
  EtherNet/IP client; backs the adapter's explicit and connected-messaging
  interop.
- **[OpENer](https://github.com/EIPStackGroup/OpENer)** — ODVA's C
  reference adapter; backs the scanner's class 1 I/O interop.

`mix test` is hermetic (292 tests, 3 properties; interop tests are excluded
by default). To run the tagged interop suites against these:

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

## EDS

`priv/eds/eipex_adapter.eds` is a sample Electronic Data Sheet matching the
[Adapter usage example](#usage-adapter) above — import it into RSNetWorx,
Studio 5000, or any ODVA EDS-aware scanner configuration tool to
pre-populate this adapter's identity and its one exclusive-owner class 1
I/O connection. Vendor and product codes in the sample are placeholders;
replace them with your ODVA-assigned values before shipping a real device.
