defmodule Eipex.Adapter.UDPTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{ConnectionTable, UDP}

  defp start_pair do
    {:ok, table} = ConnectionTable.start_link(max: 8)
    {:ok, udp} = UDP.start_link(%{port: 0, connections: table})
    {:ok, port} = UDP.port(udp)
    {table, udp, port}
  end

  test "routes datagrams to the registered io connection process" do
    {table, _udp, port} = start_pair()

    {:ok, o2t} =
      ConnectionTable.register(
        table,
        {1, 1, 1},
        %{t2o_connection_id: 9, kind: :io, pid: self()},
        self()
      )

    packet = Eipex.IO.encode_packet(o2t, 1, 1, :run, <<1, 2, 3, 4>>)
    {:ok, sender} = :gen_udp.open(0, [:binary])
    :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, packet)

    assert_receive {:io_datagram, ^packet, {_ip, _sender_port}}, 500
    :gen_udp.close(sender)
  end

  test "unknown connection ids and garbage are dropped silently" do
    {table, udp, port} = start_pair()

    {:ok, sender} = :gen_udp.open(0, [:binary])

    :ok =
      :gen_udp.send(sender, {127, 0, 0, 1}, port, Eipex.IO.encode_packet(999, 1, 1, nil, <<1>>))

    :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, <<0xDE, 0xAD>>)

    refute_receive {:io_datagram, _, _}, 200
    assert Process.alive?(udp)
    _ = table
    :gen_udp.close(sender)
  end

  test "explicit-kind connections are not io-routable" do
    {table, _udp, port} = start_pair()

    {:ok, o2t} =
      ConnectionTable.register(table, {2, 1, 1}, %{t2o_connection_id: 9}, self())

    {:ok, sender} = :gen_udp.open(0, [:binary])

    :ok =
      :gen_udp.send(sender, {127, 0, 0, 1}, port, Eipex.IO.encode_packet(o2t, 1, 1, nil, <<1>>))

    refute_receive {:io_datagram, _, _}, 200
    :gen_udp.close(sender)
  end

  test "send/4 transmits from the shared socket" do
    {_table, udp, _port} = start_pair()

    {:ok, receiver} = :gen_udp.open(0, [:binary, active: true])
    {:ok, rport} = :inet.port(receiver)

    :ok = UDP.send(udp, {127, 0, 0, 1}, rport, <<7, 7, 7>>)
    assert_receive {:udp, ^receiver, _, _, <<7, 7, 7>>}, 500
    :gen_udp.close(receiver)
  end
end
