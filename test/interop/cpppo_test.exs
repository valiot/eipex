defmodule Eipex.Interop.CpppoTest do
  @moduledoc """
  Interop against the cpppo Logix simulator (UCMM only).
  Start it first: docker compose -f interop/docker-compose.yml up -d
  Run with: mix test --include interop
  """

  use ExUnit.Case

  alias Eipex.CIP.Types
  alias Eipex.Scanner

  @moduletag :interop
  @host System.get_env("CPPPO_HOST", "127.0.0.1")

  test "registers a session, reads and writes a tag" do
    {:ok, plc} = Scanner.start_link(host: @host)

    # Write SCADA[0] = 42 (Write Tag 0x4D: type INT + element count + value)
    {:ok, write} =
      Scanner.generic_message(plc,
        service: 0x4D,
        symbolic: "SCADA",
        data: <<0xC3, 0x00, 1::16-little, 42::16-little>>
      )

    assert write.status_name == :success

    # Read it back (Read Tag 0x4C: element count)
    {:ok, read} =
      Scanner.generic_message(plc,
        service: 0x4C,
        symbolic: "SCADA",
        data: <<1::16-little>>
      )

    assert read.status_name == :success
    assert {:ok, {:int, 42}} = Types.decode_typed(read.data)

    :ok = Scanner.close(plc)
  end

  # Discovered cpppo behavior: an unresolvable symbolic path does not come
  # back as a CIP General Status error inside a normal SendRRData reply.
  # cpppo's own request handler raises an internal AssertionError
  # ("Unrecognized symbolic name ... found in path"), fails to produce a
  # CIP response, and answers with a non-zero *encapsulation*-level status
  # (decoded here as :unknown, since it isn't one of the standard encap
  # status codes) before promptly closing the TCP session. So `Scanner`
  # surfaces two effects, not one: the pending call fails with a well-formed
  # `{:error, {:encap, :unknown}}` tuple (not a crash), and shortly after,
  # the session teardown makes the linked scanner process exit with
  # `{:shutdown, :connection_lost}` — which is why a real caller of this
  # API should trap exits (or monitor instead of link) around calls whose
  # tag resolution isn't guaranteed.
  test "unknown tag fails without crashing eipex (cpppo drops the session)" do
    Process.flag(:trap_exit, true)
    {:ok, plc} = Scanner.start_link(host: @host)

    assert {:error, {:encap, _status}} =
             Scanner.generic_message(plc,
               service: 0x4C,
               symbolic: "NO_SUCH_TAG",
               data: <<1::16-little>>
             )

    assert_receive {:EXIT, ^plc, {:shutdown, :connection_lost}}, 1_000
  end
end
