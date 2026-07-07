defmodule Eipex do
  @moduledoc """
  A pure-Elixir EtherNet/IP (CIP) protocol stack, with zero runtime
  dependencies. Implements both roles — scanner (originator) and adapter
  (target) — for explicit messaging (UCMM and class 3 connected) and
  implicit messaging (class 1 cyclic I/O), plus Rockwell Logix tag services.

  ## Layers

    * **Codecs** — `Eipex.Encap`, `Eipex.CPF`, `Eipex.CIP.Path`,
      `Eipex.CIP.MessageRouter`, `Eipex.CIP.Types`,
      `Eipex.CIP.ConnectionManager` and `Eipex.CIP.Logix` are pure
      encode/decode functions for the wire formats: encapsulation framing,
      Common Packet Format, CIP EPATH, Message Router request/response,
      elementary data types, Connection Manager services (Forward
      Open/Close, Unconnected Send), and Rockwell's Logix tag services.
      No process state, no I/O.
    * **Scanner** — `Eipex.Scanner` drives a session against a remote
      device: explicit messaging, class 3 connections, class 1 cyclic I/O
      (`Eipex.Scanner.IOConnection`), device discovery
      (`Eipex.Scanner.Discovery`), and the Logix tag interface
      (`Eipex.Scanner.Logix`).
    * **Adapter** — `Eipex.Adapter` plays the target role: a TCP/UDP
      server that answers explicit messaging, serves class 1 I/O
      connections backed by application-configurable assemblies
      (`Eipex.Adapter.AssemblyStore`), and dispatches to CIP objects
      (Identity, Assembly, Connection Manager, TCP/IP Interface, Ethernet
      Link) with application behavior supplied via `Eipex.Adapter.Handler`.

  ## Getting started

  Talking to a device? Start an `Eipex.Scanner` session — see its docs for
  explicit messaging, class 3 connections, class 1 I/O, and (for Rockwell
  controllers) tag reads/writes via `Eipex.Scanner.Logix`. Acting as a
  device? Start an `Eipex.Adapter` and implement `Eipex.Adapter.Handler`
  callbacks for your application logic.

  Interop-verified against the cpppo and pycomm3 Python stacks and the
  OpENer C reference adapter — see `test/interop/`.
  """
end
