defmodule Eipex.Adapter.Listener do
  @moduledoc """
  TCP acceptor for the adapter: accepts on the adapter's pre-opened listen
  socket and hands each connection to a fresh SessionHandler under the
  sessions supervisor. The adapter opens the socket itself (before this
  process starts) so its resolved port is known in time to build the
  identity used by ListIdentity replies. Activation happens after
  `controlling_process/2` so no TCP message can race to the acceptor.
  """

  use GenServer

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @impl true
  def init(%{listen: listen, sessions_sup: sessions_sup, config: config}) do
    acceptor = spawn_link(fn -> accept_loop(listen, sessions_sup, config) end)
    {:ok, %{listen: listen, acceptor: acceptor}}
  end

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
