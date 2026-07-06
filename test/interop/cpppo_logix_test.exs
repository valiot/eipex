defmodule Eipex.Interop.CpppoLogixTest do
  @moduledoc """
  Interop: the `Eipex.Scanner.Logix` read/write/bulk layer against the real
  cpppo Logix simulator (UCMM, atomic tags).

  Start it first: docker compose -f interop/docker-compose.yml up -d
  Run with: mix test --include interop test/interop/cpppo_logix_test.exs

  cpppo reality discovered while writing this suite (not assumed up front):

    * Tag/element addressing. Real Logix — and cpppo, which mirrors its wire
      format — addresses an array element with a *separate* Element/Member
      logical path segment (CIP logical type 0x28, the 32-bit-padded form
      `Eipex.CIP.Path` calls `{:member, n}`) appended after the ANSI
      symbolic segment, never by embedding `"[n]"` inside the symbolic name
      itself. `Scanner.Logix.read/2` and `write/3` always send the given
      tag name as one opaque symbolic segment (see `request_path/1` in
      `lib/eipex/scanner.ex`), so `"SCADA[0]"` is not a name either function
      can resolve: cpppo's Symbol Object rejects the literal string with
      `Unrecognized symbolic name 'SCADA[0]'`, and — exactly as the sibling
      `cpppo_test.exs` documents for any unresolvable symbol — cpppo drops
      the session, the pending call fails with `{:error, {:encap, _}}`, and
      the linked scanner process is killed. Element-indexed addressing is
      therefore out of scope for `Scanner.Logix` as implemented; this suite
      instead exercises three distinct atomic tags (an INT array read at
      its implicit first element, plus a scalar REAL and SINT) to cover
      read, write and bulk Multiple Service Packet read.

    * Type checking. cpppo rejects a write whose CIP type code doesn't
      match the tag's declared type ("Tag type 196 ... doesn't fit within
      Attribute type 195") with CIP general status 0xFF
      (`:general_error`) and an extended-status word — this is what backs
      the "wrong type" test below. `Scanner.Logix.write/4` without an
      explicit `type:` infers a bare integer as DINT, so SCADA (declared
      INT in cpppo) and Flag (declared SINT) both need `type:` passed
      explicitly, exactly as a live `tag_list/2` catalog would supply.

  `tag_list/2` is deliberately not exercised here: cpppo's Symbol Object
  support isn't a faithful stand-in for a real Logix controller (no
  Get_Instance_Attribute_List continuation semantics), and that path is
  already covered hermetically (see `test/eipex/scanner/logix_test.exs`).
  """

  use ExUnit.Case

  alias Eipex.Scanner

  @moduletag :interop
  @moduletag timeout: 300_000
  @host System.get_env("CPPPO_HOST", "127.0.0.1")

  test "writes and reads back a scalar tag" do
    {:ok, plc} = Scanner.start_link(host: @host)

    assert :ok = Scanner.Logix.write(plc, "SCADA", 42, type: :int)
    assert {:ok, %Eipex.Tag{value: 42, type: :int, error: nil}} = Scanner.Logix.read(plc, "SCADA")

    :ok = Scanner.close(plc)
  end

  test "bulk read returns multiple tags in order via a Multiple Service Packet" do
    {:ok, plc} = Scanner.start_link(host: @host)

    :ok = Scanner.Logix.write(plc, "SCADA", 7, type: :int)
    :ok = Scanner.Logix.write(plc, "Rate", 3.5)
    :ok = Scanner.Logix.write(plc, "Flag", 1, type: :sint)

    assert {:ok, [scada, rate, flag]} = Scanner.Logix.read(plc, ["SCADA", "Rate", "Flag"])

    assert %Eipex.Tag{name: "SCADA", value: 7, type: :int, error: nil} = scada
    assert %Eipex.Tag{name: "Rate", value: 3.5, type: :real, error: nil} = rate
    assert %Eipex.Tag{name: "Flag", value: 1, type: :sint, error: nil} = flag

    :ok = Scanner.close(plc)
  end

  test "a write with the wrong CIP type surfaces as a CIP error, not a crash" do
    {:ok, plc} = Scanner.start_link(host: @host)

    :ok = Scanner.Logix.write(plc, "SCADA", 11, type: :int)

    # SCADA is declared INT (16-bit) in cpppo; forcing DINT (32-bit) trips
    # cpppo's own type check instead of silently truncating or padding.
    assert {:error, {:cip, :general_error, _extended}} =
             Scanner.Logix.write(plc, "SCADA", 99, type: :dint)

    assert {:ok, %Eipex.Tag{value: 11, type: :int, error: nil}} = Scanner.Logix.read(plc, "SCADA")

    :ok = Scanner.close(plc)
  end
end
