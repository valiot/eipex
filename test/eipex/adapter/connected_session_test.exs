defmodule Eipex.Adapter.ConnectedSessionTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

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
    %Encap{command: :register_session, session_handle: handle} = recv_frame(socket)
    handle
  end

  defp open_connection(socket, handle, serial \\ 1) do
    fo = %CM.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: 0x1122_3344,
      connection_serial: serial,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      timeout_multiplier: 1,
      o2t_rpi: 10_000_000,
      o2t_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :variable,
        size: 500
      },
      t2o_rpi: 10_000_000,
      t2o_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :variable,
        size: 500
      },
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(class: 0x02, instance: 0x01)
    }

    cpf = CPF.encode([:null_address, {:unconnected_data, CM.encode_forward_open(fo, :standard)}])
    send_frame(socket, Encap.send_rr_data(handle, cpf))

    reply = recv_frame(socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)
    [{:unconnected_data, mr}] = for {:unconnected_data, _} = i <- items, do: i
    {:ok, %{status_name: :success, data: data}} = MR.decode_response(mr)
    {:ok, fo_reply} = CM.decode_forward_open_reply(data)
    fo_reply.o2t_connection_id
  end

  defp unit_frame(handle, conn_id, seq, mr) do
    cpf =
      CPF.encode([
        {:connected_address, conn_id},
        {:connected_data, <<seq::16-little, mr::binary>>}
      ])

    Encap.send_unit_data(handle, cpf)
  end

  defp unit_response(frame) do
    {:ok, cpf} = Encap.unwrap_cpf(frame)
    {:ok, items} = CPF.decode(cpf)
    [{:connected_address, id}] = for {:connected_address, _} = i <- items, do: i

    [{:connected_data, <<seq::16-little, mr::binary>>}] =
      for {:connected_data, _} = i <- items, do: i

    {:ok, response} = MR.decode_response(mr)
    {id, seq, response}
  end

  test "serves connected requests with sequence echo on the t2o id" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)
    o2t = open_connection(socket, handle)

    mr = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    send_frame(socket, unit_frame(handle, o2t, 1, mr))

    {id, seq, response} = unit_response(recv_frame(socket))
    assert id == 0x1122_3344
    assert seq == 1
    assert response.status_name == :success
    assert response.data == <<0x4D, 0x00>>
  end

  test "retransmissions with the same sequence resend the cached reply without side effects" do
    {pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)
    o2t = open_connection(socket, handle)

    write = MR.encode_request(0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2, 3, 4>>)
    send_frame(socket, unit_frame(handle, o2t, 5, write))
    {_id, 5, %{status_name: :success}} = unit_response(recv_frame(socket))

    # mutate the assembly out-of-band, then retransmit seq 5: the cached success
    # reply must come back and the store must NOT be overwritten again
    :ok = Eipex.Adapter.write_assembly(pid, 150, <<9, 9, 9, 9>>)
    send_frame(socket, unit_frame(handle, o2t, 5, write))
    {_id, 5, %{status_name: :success}} = unit_response(recv_frame(socket))

    assert {:ok, <<9, 9, 9, 9>>} = Eipex.Adapter.read_assembly(pid, 150)
  end

  test "unknown connection ids are dropped silently" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)
    _o2t = open_connection(socket, handle)

    mr = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    send_frame(socket, unit_frame(handle, 0xDEAD_BEEF, 1, mr))

    assert {:error, :timeout} = :gen_tcp.recv(socket, 0, 300)
  end

  test "send_unit_data with a wrong session handle answers 0x64" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    _handle = register(socket)

    send_frame(socket, Encap.send_unit_data(0xBAD, <<>>))
    assert %Encap{command: :send_unit_data, status: 0x0064} = recv_frame(socket)
  end

  test "malformed connected payloads answer 0x0003" do
    {_pid, port} = start_adapter()
    socket = connect(port)
    handle = register(socket)

    send_frame(socket, Encap.send_unit_data(handle, <<0xFF>>))
    assert %Encap{command: :send_unit_data, status: 0x0003} = recv_frame(socket)
  end

  test "a connection opened on one session is not servable from another" do
    {_pid, port} = start_adapter()
    socket1 = connect(port)
    handle1 = register(socket1)
    o2t = open_connection(socket1, handle1)

    socket2 = connect(port)
    handle2 = register(socket2)

    mr = MR.encode_request(0x0E, class: 0x01, instance: 1, attribute: 1)
    send_frame(socket2, unit_frame(handle2, o2t, 1, mr))
    assert {:error, :timeout} = :gen_tcp.recv(socket2, 0, 300)
  end
end
