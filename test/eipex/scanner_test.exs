defmodule Eipex.ScannerTest do
  use ExUnit.Case

  alias Eipex.Scanner
  alias Eipex.TestSupport.ScriptedTarget
  alias Eipex.CIP.MessageRouter

  defp noop_handler, do: fn _mr -> :no_reply end

  defp get_attr_handler(reply_data) do
    fn mr ->
      {:ok, %{service: 0x0E, path: _path, data: <<>>}} = MessageRouter.decode_request(mr)
      MessageRouter.encode_response(0x0E, 0x00, data: reply_data)
    end
  end

  defp start_scanner(target, opts \\ []) do
    {:ok, pid} =
      Scanner.start_link([host: {127, 0, 0, 1}, port: target.port] ++ opts)

    pid
  end

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

  describe "generic_message/2" do
    test "round-trips a UCMM request" do
      target = ScriptedTarget.start(get_attr_handler(<<0x4D, 0x00>>))
      pid = start_scanner(target)

      assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 0x01, instance: 1, attribute: 1)

      Scanner.close(pid)
    end

    test "reassembles responses split across TCP segments" do
      target = ScriptedTarget.start(get_attr_handler(<<1, 2, 3, 4>>), split_replies: true)
      pid = start_scanner(target)

      assert {:ok, %{status_name: :success, data: <<1, 2, 3, 4>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 0x01, instance: 1, attribute: 1)

      Scanner.close(pid)
    end

    test "returns CIP errors inside the ok tuple" do
      handler = fn _mr -> MessageRouter.encode_response(0x0E, 0x05) end
      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:ok, %{status: 0x05, status_name: :path_destination_unknown}} =
               Scanner.generic_message(pid, service: 0x0E, class: 0x77, instance: 9, attribute: 1)

      Scanner.close(pid)
    end

    test "times out when the target does not answer, and recovers" do
      calls = :counters.new(1, [])

      handler = fn mr ->
        :counters.add(calls, 1, 1)

        if :counters.get(calls, 1) == 1 do
          :no_reply
        else
          {:ok, %{service: service}} = MessageRouter.decode_request(mr)
          MessageRouter.encode_response(service, 0x00, data: <<0xAA>>)
        end
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:error, :timeout} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 100)

      assert {:ok, %{data: <<0xAA>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1)

      Scanner.close(pid)
    end

    test "serializes concurrent requests through the queue" do
      handler = fn mr ->
        {:ok, %{service: 0x0E, path: path}} = MessageRouter.decode_request(mr)
        {:ok, segments} = Eipex.CIP.Path.decode(path)
        instance = Keyword.fetch!(segments, :instance)
        MessageRouter.encode_response(0x0E, 0x00, data: <<instance>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      tasks =
        for i <- 1..5 do
          Task.async(fn ->
            Scanner.generic_message(pid, service: 0x0E, class: 1, instance: i)
          end)
        end

      results = Task.await_many(tasks, 5_000)

      for {result, i} <- Enum.zip(results, 1..5) do
        assert {:ok, %{data: <<^i>>}} = result
      end

      Scanner.close(pid)
    end

    test "symbolic option builds an ANSI symbolic path" do
      handler = fn mr ->
        {:ok, %{service: 0x4C, path: <<0x91, 0x05, "SCADA", 0x00>>}} =
          MessageRouter.decode_request(mr)

        MessageRouter.encode_response(0x4C, 0x00, data: <<0xC3, 0x00, 7, 0>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:ok, %{status_name: :success}} =
               Scanner.generic_message(pid,
                 service: 0x4C,
                 symbolic: "SCADA",
                 data: <<1::16-little>>
               )

      Scanner.close(pid)
    end

    test "missing service or path returns an error without touching the wire" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target)

      assert {:error, :missing_service} = Scanner.generic_message(pid, class: 1)
      assert {:error, :missing_path} = Scanner.generic_message(pid, service: 0x0E)

      Scanner.close(pid)
    end

    test "request timeout defaults to the session timeout" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)

      {:ok, pid} =
        Scanner.start_link(host: {127, 0, 0, 1}, port: target.port, timeout: 200)

      {elapsed_us, result} =
        :timer.tc(fn ->
          Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1)
        end)

      assert {:error, :timeout} = result
      assert elapsed_us < 2_000_000

      Scanner.close(pid)
    end
  end
end
