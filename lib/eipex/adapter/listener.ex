defmodule Eipex.Adapter.Listener do
  @moduledoc """
  TCP acceptor for the adapter: accepts on the configured port and hands
  each connection to a fresh SessionHandler under the sessions supervisor.
  Activation happens after `controlling_process/2` so no TCP message can
  race to the acceptor.
  """

  use GenServer

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def port(listener), do: GenServer.call(listener, :port)

  @impl true
  def init(%{port: port, ip: ip, sessions_sup: sessions_sup, config: config}) do
    listen_opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip]

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, listen} ->
        acceptor = spawn_link(fn -> accept_loop(listen, sessions_sup, config) end)
        {:ok, %{listen: listen, acceptor: acceptor}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, :inet.port(state.listen), state}

  defp accept_loop(listen, sessions_sup, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        {:ok, pid} =
          DynamicSupervisor.start_child(
            sessions_sup,
            {Eipex.Adapter.SessionHandler, {socket, config}}
          )

        :ok = :gen_tcp.controlling_process(socket, pid)
        Eipex.Adapter.SessionHandler.activate(pid)
        accept_loop(listen, sessions_sup, config)

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        # avoid hot-spinning on emfile/enfile during fd exhaustion
        Process.sleep(100)
        accept_loop(listen, sessions_sup, config)
    end
  end
end
