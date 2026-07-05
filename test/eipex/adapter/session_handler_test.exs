defmodule Eipex.Adapter.SessionHandlerTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap}

  @identity [
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex Adapter"
  ]

  defp start_adapter(extra \\ []) do
    {:ok, pid} =
      Eipex.Adapter.start_link(
        [identity: @identity, assemblies: [output: [instance: 150, size: 4]], port: 0] ++ extra
      )

    {:ok, port} = Eipex.Adapter.port(pid)
    {pid, port}
  end

  defp connect(port) do
    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, packet: :raw, active: false])

    socket
  end

  defp send_frame(socket, frame), do: :ok = :gen_tcp.send(socket, Encap.encode(frame))

  defp recv_frame(socket, buffer \\ <<>>) do
    {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)

    case Encap.decode(buffer <> data) do
      {:ok, frame, _rest} -> frame
      :partial -> recv_frame(socket, buffer <> data)
    end
  end

  defp register(socket) do
    send_frame(socket, Encap.register_session())
    %Encap{command: :register_session, status: 0, session_handle: handle} = recv_frame(socket)
    assert handle != 0
    handle
  end

  test "registers a session and answers identity over UCMM" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)

    mr = Eipex.CIP.MessageRouter.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}])
    send_frame(socket, %Encap{Encap.send_rr_data(handle, cpf) | sender_context: <<7::64>>})

    reply = recv_frame(socket)
    assert %Encap{command: :send_rr_data, status: 0, sender_context: <<7::64>>} = reply
    {:ok, items} = reply |> Encap.unwrap_cpf() |> then(fn {:ok, c} -> CPF.decode(c) end)
    [{:unconnected_data, response}] = for {:unconnected_data, _} = i <- items, do: i

    assert {:ok, %{status_name: :success, data: <<0x4D, 0x00>>}} =
             Eipex.CIP.MessageRouter.decode_response(response)
  end

  test "second register on the same connection is rejected" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)

    send_frame(socket, Encap.register_session())
    assert %Encap{command: :register_session, status: 0x0001} = recv_frame(socket)
  end

  test "send_rr_data with a wrong session handle answers 0x64" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)

    send_frame(socket, Encap.send_rr_data(0xDEAD, <<>>))
    assert %Encap{command: :send_rr_data, status: 0x0064} = recv_frame(socket)
  end

  test "malformed CPF answers 0x0003" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)

    send_frame(socket, Encap.send_rr_data(handle, <<0xFF>>))
    assert %Encap{command: :send_rr_data, status: 0x0003} = recv_frame(socket)
  end

  test "unknown commands echo with status 0x0001" do
    {_pid, port} = start_adapter()
    socket = connect(port)

    send_frame(socket, %Encap{command: {:unknown, 0xAB}, sender_context: <<1::64>>})

    assert %Encap{command: {:unknown, 0xAB}, status: 0x0001, sender_context: <<1::64>>} =
             recv_frame(socket)
  end

  test "list_identity and list_services answer over TCP without a session" do
    {_pid, port} = start_adapter()
    socket = connect(port)

    send_frame(socket, Encap.list_identity())
    reply = recv_frame(socket)
    {:ok, [{:identity, id}]} = CPF.decode(reply.data)
    assert id.product_name == "Eipex Adapter"

    send_frame(socket, %Encap{command: :list_services})

    assert %Encap{
             command: :list_services,
             data:
               <<1::16-little, 0x0100::16-little, 20::16-little, 1::16-little, 0x0020::16-little,
                 "Communications", 0, 0>>
           } = recv_frame(socket)
  end

  test "inactivity timeout closes the connection" do
    {_pid, port} = start_adapter(inactivity_timeout: 100)
    socket = connect(port)
    _handle = register(socket)

    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
  end

  test "a crashed session handler does not kill the listener" do
    {pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)
    :gen_tcp.close(socket)

    Process.sleep(50)
    socket2 = connect(port)
    assert register(socket2) != 0
    assert Process.alive?(pid)
  end
end
