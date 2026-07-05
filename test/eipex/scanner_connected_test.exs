defmodule Eipex.ScannerConnectedTest do
  use ExUnit.Case

  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter
  alias Eipex.Scanner
  alias Eipex.TestSupport.ScriptedTarget

  defp fo_success_handler(opts \\ []) do
    o2t = Keyword.get(opts, :o2t_id, 0xAAAA_0001)
    reject_large = Keyword.get(opts, :reject_large, false)

    fn mr ->
      case MessageRouter.decode_request(mr) do
        {:ok, %{service: 0x5B, data: data}} when reject_large ->
          {:ok, fo} = CM.decode_forward_open(0x5B, data)
          _ = fo
          MessageRouter.encode_response(0x5B, 0x01, extended: [0x0128])

        {:ok, %{service: service, data: data}} when service in [0x54, 0x5B] ->
          {:ok, fo} = CM.decode_forward_open(service, data)

          reply = %CM.ForwardOpenReply{
            o2t_connection_id: o2t,
            t2o_connection_id: fo.t2o_connection_id,
            connection_serial: fo.connection_serial,
            originator_vendor_id: fo.originator_vendor_id,
            originator_serial: fo.originator_serial,
            o2t_api: fo.o2t_rpi,
            t2o_api: fo.t2o_rpi,
            application_reply: <<>>
          }

          MessageRouter.encode_response(service, 0x00, data: CM.encode_forward_open_reply(reply))

        {:ok, %{service: 0x4E, data: data}} ->
          {:ok, fc} = CM.decode_forward_close(data)

          MessageRouter.encode_response(0x4E, 0x00, data: CM.encode_forward_close_reply(fc))
      end
    end
  end

  defp start_scanner(target, opts \\ []) do
    {:ok, pid} =
      Scanner.start_link(
        [host: {127, 0, 0, 1}, port: target.port, vendor_id: 0x004D, serial_number: 0xDEAD_0001] ++
          opts
      )

    pid
  end

  test "forward_open stores the connection with large params by default" do
    target = ScriptedTarget.start(fo_success_handler())
    pid = start_scanner(target)

    assert {:ok, conn} = Scanner.forward_open(pid)
    assert conn.o2t_connection_id == 0xAAAA_0001
    assert conn.variant == :large
    assert conn.size == 4002
    assert conn.connection_serial == 1

    assert {:error, :already_connected} = Scanner.forward_open(pid)
    Scanner.close(pid)
  end

  test "large rejection falls back to a standard forward open" do
    target = ScriptedTarget.start(fo_success_handler(reject_large: true))
    pid = start_scanner(target)

    assert {:ok, %{variant: :standard, size: 500}} = Scanner.forward_open(pid)
    Scanner.close(pid)
  end

  test "standard rejection reports the CIP error without retry" do
    handler = fn mr ->
      {:ok, %{service: service}} = MessageRouter.decode_request(mr)
      MessageRouter.encode_response(service, 0x01, extended: [0x0113])
    end

    target = ScriptedTarget.start(handler)
    pid = start_scanner(target)

    assert {:error, {:cip, :connection_failure, [0x0113]}} =
             Scanner.forward_open(pid, variant: :standard)

    Scanner.close(pid)
  end

  test "forward_close clears the connection" do
    target = ScriptedTarget.start(fo_success_handler())
    pid = start_scanner(target)

    assert {:error, :no_connection} = Scanner.forward_close(pid)
    {:ok, _conn} = Scanner.forward_open(pid)
    assert :ok = Scanner.forward_close(pid)
    assert {:error, :no_connection} = Scanner.forward_close(pid)

    # can open again after closing
    assert {:ok, %{connection_serial: 2}} = Scanner.forward_open(pid)
    Scanner.close(pid)
  end

  test "forward open request carries the configured identity and MR path" do
    test_pid = self()

    handler = fn mr ->
      {:ok, %{service: 0x5B, data: data}} = MessageRouter.decode_request(mr)
      {:ok, fo} = CM.decode_forward_open(0x5B, data)
      send(test_pid, {:fo, fo})

      reply = %CM.ForwardOpenReply{
        o2t_connection_id: 1,
        t2o_connection_id: fo.t2o_connection_id,
        connection_serial: fo.connection_serial,
        originator_vendor_id: fo.originator_vendor_id,
        originator_serial: fo.originator_serial,
        o2t_api: fo.o2t_rpi,
        t2o_api: fo.t2o_rpi,
        application_reply: <<>>
      }

      MessageRouter.encode_response(0x5B, 0x00, data: CM.encode_forward_open_reply(reply))
    end

    target = ScriptedTarget.start(handler)
    pid = start_scanner(target)
    {:ok, _} = Scanner.forward_open(pid)

    assert_receive {:fo, fo}
    assert fo.originator_vendor_id == 0x004D
    assert fo.originator_serial == 0xDEAD_0001
    assert fo.transport == %{direction: :server, trigger: :application, class: 3}
    assert {:ok, [class: 0x02, instance: 0x01]} = Eipex.CIP.Path.decode(fo.connection_path)

    Scanner.close(pid)
  end
end
