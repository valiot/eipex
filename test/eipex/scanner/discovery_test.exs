defmodule Eipex.Scanner.DiscoveryTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap, Identity}
  alias Eipex.Scanner.Discovery

  @identity %Identity{
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex",
    ip: {127, 0, 0, 1},
    port: 44_818,
    state: 3
  }

  # A one-shot UDP responder speaking the real protocol.
  defp start_responder(reply_fun) do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(socket)

    Task.start_link(fn ->
      {:ok, {ip, sport, data}} = :gen_udp.recv(socket, 0, 5_000)
      {:ok, %Encap{command: :list_identity}, <<>>} = Encap.decode(data)

      case reply_fun.() do
        nil -> :ok
        reply -> :gen_udp.send(socket, ip, sport, reply)
      end

      :gen_udp.close(socket)
    end)

    port
  end

  test "discover collects identity items from replies" do
    reply =
      Encap.encode(%Encap{
        command: :list_identity,
        data: CPF.encode([{:identity, @identity}])
      })

    port = start_responder(fn -> reply end)

    assert {:ok, [%Identity{product_name: "Eipex", vendor_id: 0x4D}]} =
             Discovery.discover(address: {127, 0, 0, 1}, port: port, timeout: 300)
  end

  test "discover ignores malformed datagrams" do
    port = start_responder(fn -> <<0xDE, 0xAD, 0xBE, 0xEF>> end)

    assert {:ok, []} = Discovery.discover(address: {127, 0, 0, 1}, port: port, timeout: 300)
  end

  test "discover returns empty list when nobody answers" do
    port = start_responder(fn -> nil end)

    assert {:ok, []} = Discovery.discover(address: {127, 0, 0, 1}, port: port, timeout: 200)
  end

  test "Eipex.Scanner.discover/1 delegates" do
    port = start_responder(fn -> nil end)

    assert {:ok, []} =
             Eipex.Scanner.discover(address: {127, 0, 0, 1}, port: port, timeout: 200)
  end

  test "send failure returns an error and does not leak the socket" do
    ports_before = length(:erlang.ports())

    # Run multiple times - if sockets are leaking, port count would keep growing
    for _ <- 1..5 do
      assert {:error, :einval} =
               Discovery.discover(address: {127, 0, 0, 1}, port: 0, timeout: 50)
    end

    :erlang.garbage_collect()
    :timer.sleep(100)

    ports_after = length(:erlang.ports())

    # Verify ports haven't accumulated from multiple failures
    # Should be at most one extra port (from Erlang UDP error handling)
    assert ports_after <= ports_before + 1,
           "Socket leak detected: ports went from #{ports_before} to #{ports_after}"
  end
end
