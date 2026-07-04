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

    ref = Process.monitor(pid)
    assert :ok = Scanner.close(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000

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

  # Splits an Unconnected Send request payload into {embedded_mr, route_path_bytes}.
  defp unwrap_unconnected_send(data) do
    <<_ptt, _ticks, size::16-little, embedded::binary-size(size), rest::binary>> = data
    rest = if rem(size, 2) == 1, do: binary_part(rest, 1, byte_size(rest) - 1), else: rest
    <<route_words, 0x00, route::binary-size(route_words * 2)>> = rest
    {embedded, route}
  end

  describe "route_path" do
    test "wraps requests in Unconnected Send and replies with the embedded response" do
      handler = fn mr ->
        {:ok, %{service: 0x52, path: <<0x20, 0x06, 0x24, 0x01>>, data: data}} =
          MessageRouter.decode_request(mr)

        {embedded, route} = unwrap_unconnected_send(data)
        assert route == <<0x01, 0x00>>

        {:ok, %{service: 0x0E}} = MessageRouter.decode_request(embedded)
        MessageRouter.encode_response(0x0E, 0x00, data: <<0x63>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target, route_path: [backplane: 0])

      assert {:ok, %{status_name: :success, data: <<0x63>>}} =
               Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, attribute: 7)

      Scanner.close(pid)
    end

    test "per-request route_path overrides the session default" do
      handler = fn mr ->
        # session default would wrap in Unconnected Send (0x52);
        # the per-request :none override must arrive unwrapped
        {:ok, %{service: 0x0E}} = MessageRouter.decode_request(mr)
        MessageRouter.encode_response(0x0E, 0x00, data: <<1>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target, route_path: [backplane: 0])

      assert {:ok, %{status_name: :success}} =
               Scanner.generic_message(pid,
                 service: 0x0E,
                 class: 1,
                 instance: 1,
                 route_path: :none
               )

      Scanner.close(pid)
    end
  end

  describe "attribute helpers" do
    test "get_attribute returns the raw attribute data" do
      target = ScriptedTarget.start(get_attr_handler(<<0x4D, 0x00>>))
      pid = start_scanner(target)

      assert {:ok, <<0x4D, 0x00>>} = Scanner.get_attribute(pid, 0x01, 1, 1)
      Scanner.close(pid)
    end

    test "get_attribute surfaces CIP errors as error tuples" do
      handler = fn _mr -> MessageRouter.encode_response(0x0E, 0x14, extended: [0x0001]) end
      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:error, {:cip, :attribute_not_supported, [0x0001]}} =
               Scanner.get_attribute(pid, 0x01, 1, 99)

      Scanner.close(pid)
    end

    test "set_attribute returns :ok on success" do
      handler = fn mr ->
        {:ok, %{service: 0x10, data: <<0x01>>}} = MessageRouter.decode_request(mr)
        MessageRouter.encode_response(0x10, 0x00)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert :ok = Scanner.set_attribute(pid, 0xF5, 1, 8, <<0x01>>)
      Scanner.close(pid)
    end

    test "get_attributes_all uses service 0x01 without an attribute segment" do
      handler = fn mr ->
        {:ok, %{service: 0x01, path: <<0x20, 0x01, 0x24, 0x01>>}} =
          MessageRouter.decode_request(mr)

        MessageRouter.encode_response(0x01, 0x00, data: <<9, 9>>)
      end

      target = ScriptedTarget.start(handler)
      pid = start_scanner(target)

      assert {:ok, <<9, 9>>} = Scanner.get_attributes_all(pid, 0x01, 1)
      Scanner.close(pid)
    end
  end

  describe "keepalive and connection loss" do
    test "sends NOP frames at the configured interval" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target, keepalive: 50)

      Process.sleep(180)
      Scanner.close(pid)
      Process.sleep(50)

      nops = target |> ScriptedTarget.frames() |> Enum.count(&(&1.command == :nop))
      assert nops >= 2
    end

    test "keepalive: :none sends no NOPs" do
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target, keepalive: :none)

      Process.sleep(150)
      Scanner.close(pid)
      Process.sleep(50)

      assert target |> ScriptedTarget.frames() |> Enum.count(&(&1.command == :nop)) == 0
    end

    test "connection loss fails the in-flight caller and stops the process" do
      Process.flag(:trap_exit, true)
      target = ScriptedTarget.start(fn _ -> :no_reply end)
      pid = start_scanner(target)
      ref = Process.monitor(pid)

      caller =
        Task.async(fn ->
          Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 5_000)
        end)

      # let the request reach the wire, then drop the connection target-side
      Process.sleep(50)
      ScriptedTarget.close(target)

      assert {:error, :connection_lost} = Task.await(caller, 1_000)
      assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :connection_lost}}, 1_000
    end

    test "send failure on a subsequent request reports connection_lost, not a badmatch" do
      Process.flag(:trap_exit, true)

      handler = fn mr ->
        {:ok, %{service: 0x0E}} = MessageRouter.decode_request(mr)
        MessageRouter.encode_response(0x0E, 0x00, data: <<1>>)
      end

      target = ScriptedTarget.start(handler, rst_after_reply: true)
      pid = start_scanner(target)
      ref = Process.monitor(pid)

      first =
        Task.async(fn ->
          Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 1, timeout: 2_000)
        end)

      # the target holds its reply for a while (see rst_after_reply above),
      # so this has ample room to land in the queue behind the first request
      # before the reply (and reset) arrive
      Process.sleep(10)

      second =
        Task.async(fn ->
          Scanner.generic_message(pid, service: 0x0E, class: 1, instance: 2, timeout: 2_000)
        end)

      assert {:ok, %{data: <<1>>}} = Task.await(first, 1_000)
      assert {:error, :connection_lost} = Task.await(second, 1_000)

      assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :connection_lost}}, 1_000
      refute_received {:DOWN, ^ref, :process, ^pid, {{:badmatch, _}, _}}
    end
  end
end
