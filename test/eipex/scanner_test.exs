defmodule Eipex.ScannerTest do
  use ExUnit.Case

  alias Eipex.Scanner
  alias Eipex.TestSupport.ScriptedTarget

  defp noop_handler, do: fn _mr -> :no_reply end

  test "start_link registers a session and close unregisters it" do
    target = ScriptedTarget.start(noop_handler())

    {:ok, pid} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)
    assert_receive {:scripted_target_connected, _}, 1_000

    assert :ok = Scanner.close(pid)
    refute Process.alive?(pid)

    # give the target loop a beat to decode the trailing frames
    Process.sleep(50)

    commands = target |> ScriptedTarget.frames() |> Enum.map(& &1.command)
    assert commands == [:register_session, :unregister_session]
  end

  test "start_link returns an error when nothing listens" do
    Process.flag(:trap_exit, true)
    assert {:error, :econnrefused} = Scanner.start_link(host: {127, 0, 0, 1}, port: 1)
  end

  test "session handle from the target is stored and used" do
    target = ScriptedTarget.start(noop_handler())
    {:ok, pid} = Scanner.start_link(host: {127, 0, 0, 1}, port: target.port)

    assert %{session_handle: 0x1234} = :sys.get_state(pid)
    Scanner.close(pid)
  end
end
