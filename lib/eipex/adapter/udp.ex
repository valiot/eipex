defmodule Eipex.Adapter.UDP do
  @moduledoc """
  The adapter's shared class 1 I/O socket (default UDP 2222). Inbound
  datagrams are demultiplexed by the 32-bit connection ID in the Sequenced
  Address item and forwarded to the owning connection process; everything
  unroutable is dropped (UDP has no error channel). Outbound sends are
  serialized through this process (the socket owner).
  """

  use GenServer

  alias Eipex.Adapter.ConnectionTable
  alias Eipex.CPF

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def port(server), do: GenServer.call(server, :port)

  @spec send(GenServer.server(), :inet.ip4_address(), :inet.port_number(), binary()) :: :ok
  def send(server, ip, port, packet), do: GenServer.cast(server, {:send, ip, port, packet})

  @impl true
  def init(%{port: port, connections: connections} = init_arg) do
    multicast_opts =
      case init_arg[:multicast] do
        %{interface: interface, ttl: ttl} -> [multicast_if: interface, multicast_ttl: ttl]
        nil -> []
      end

    case :gen_udp.open(port, [:binary, active: true, reuseaddr: true] ++ multicast_opts) do
      {:ok, socket} -> {:ok, %{socket: socket, connections: connections}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, :inet.port(state.socket), state}

  @impl true
  def handle_cast({:send, ip, port, packet}, state) do
    _ = :gen_udp.send(state.socket, ip, port, packet)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, socket, ip, port, datagram}, %{socket: socket} = state) do
    with {:ok, items} <- CPF.decode(datagram),
         [{:sequenced_address, conn_id, _seq}] <-
           for({:sequenced_address, _, _} = i <- items, do: i),
         {:ok, %{kind: :io, pid: pid}} <-
           ConnectionTable.lookup_o2t(state.connections, conn_id) do
      Kernel.send(pid, {:io_datagram, datagram, {ip, port}})
    else
      _ -> :ok
    end

    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}
end
