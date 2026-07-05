defmodule Eipex.Adapter.Discovery do
  @moduledoc """
  UDP ListIdentity responder (port 44818). Replies are delayed by a uniform
  random interval to avoid response storms on broadcast discovery
  (ODVA-recommended behavior).
  """

  use GenServer

  alias Eipex.{CPF, Encap}

  def start_link(init_arg), do: GenServer.start_link(__MODULE__, init_arg)

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def port(server), do: GenServer.call(server, :port)

  @impl true
  def init(%{port: port, delay: delay, config: config}) do
    case :gen_udp.open(port, [:binary, active: true, reuseaddr: true]) do
      {:ok, socket} -> {:ok, %{socket: socket, delay: delay, config: config}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, :inet.port(state.socket), state}

  @impl true
  def handle_info({:udp, socket, ip, port, data}, %{socket: socket} = state) do
    case Encap.decode(data) do
      {:ok, %Encap{command: :list_identity} = frame, _rest} ->
        Process.send_after(self(), {:respond, ip, port, frame}, random_delay(state.delay))

      _ ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info({:respond, ip, port, frame}, state) do
    reply = %Encap{frame | data: CPF.encode([{:identity, state.config.identity}])}
    _ = :gen_udp.send(state.socket, ip, port, Encap.encode(reply))
    {:noreply, state}
  end

  defp random_delay({min, max}) when max > min, do: min + :rand.uniform(max - min + 1) - 1
  defp random_delay({min, _}), do: min
end
