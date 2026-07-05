defmodule Eipex.Adapter.SessionHandler do
  @moduledoc """
  One process per TCP connection: encapsulation framing, session handle
  lifecycle, and UCMM dispatch. Dies quietly on disconnect
  (`restart: :temporary`) without touching the listener.
  """

  use GenServer, restart: :temporary

  alias Eipex.{CPF, Encap}
  alias Eipex.Adapter.MessageRouter

  def start_link({socket, config}), do: GenServer.start_link(__MODULE__, {socket, config})

  def activate(pid), do: GenServer.cast(pid, :activate)

  @impl true
  def init({socket, config}) do
    {:ok,
     %{
       socket: socket,
       config: config,
       buffer: <<>>,
       session_handle: nil,
       timer: nil,
       closing: false
     }}
  end

  @impl true
  def handle_cast(:activate, state) do
    :ok = :inet.setopts(state.socket, active: :once)
    {:noreply, arm_inactivity(state)}
  end

  @impl true
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    state = drain(%{state | buffer: state.buffer <> data})
    :ok = :inet.setopts(socket, active: :once)
    {:noreply, arm_inactivity(state)}
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state), do: {:stop, :normal, state}
  def handle_info({:tcp_error, socket, _}, %{socket: socket} = state), do: {:stop, :normal, state}

  def handle_info(:inactivity_timeout, state) do
    :gen_tcp.close(state.socket)
    {:stop, {:shutdown, :inactivity_timeout}, state}
  end

  def handle_info(:stop_normal, state), do: {:stop, :normal, state}

  # -- Frame handling ------------------------------------------------------------

  defp drain(%{closing: true} = state), do: state

  defp drain(state) do
    case Encap.decode(state.buffer) do
      {:ok, frame, rest} -> %{state | buffer: rest} |> handle_frame(frame) |> drain()
      :partial -> state
    end
  end

  defp handle_frame(state, %Encap{command: :register_session} = frame) do
    if state.session_handle do
      reply(state, %Encap{frame | status: 0x0001})
      state
    else
      handle = :erlang.unique_integer([:positive]) |> rem(0xFFFF_FFFE) |> Kernel.+(1)
      reply(state, %Encap{frame | session_handle: handle})
      %{state | session_handle: handle}
    end
  end

  defp handle_frame(state, %Encap{command: :unregister_session}) do
    :gen_tcp.close(state.socket)
    # finish draining this packet, then stop; no reply is defined for unregister
    send(self(), :stop_normal)
    %{state | closing: true}
  end

  defp handle_frame(state, %Encap{command: :send_rr_data, session_handle: handle} = frame) do
    cond do
      is_nil(state.session_handle) or handle != state.session_handle ->
        reply(state, %Encap{frame | status: 0x0064, data: <<>>})

      true ->
        case rr_payload(frame) do
          {:ok, mr_request} ->
            response = MessageRouter.dispatch(state.config, mr_request)
            cpf = CPF.encode([:null_address, {:unconnected_data, response}])

            reply(state, %Encap{
              Encap.send_rr_data(state.session_handle, cpf)
              | sender_context: frame.sender_context
            })

          {:error, _} ->
            reply(state, %Encap{frame | status: 0x0003, data: <<>>})
        end
    end

    state
  end

  defp handle_frame(state, %Encap{command: :nop}), do: state

  defp handle_frame(state, %Encap{command: :list_identity} = frame) do
    reply(state, %Encap{frame | data: CPF.encode([{:identity, state.config.identity}])})
    state
  end

  defp handle_frame(state, %Encap{command: :list_services} = frame) do
    item =
      <<1::16-little, 0x0100::16-little, 20::16-little, 1::16-little, 0x0020::16-little,
        "Communications", 0, 0>>

    reply(state, %Encap{frame | data: item})
    state
  end

  # send_unit_data (phase 4) and unknown commands: invalid command
  defp handle_frame(state, %Encap{} = frame) do
    reply(state, %Encap{frame | status: 0x0001, data: <<>>})
    state
  end

  defp rr_payload(frame) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [mr | _] <- for({:unconnected_data, d} <- items, do: d) do
      {:ok, mr}
    else
      _ -> {:error, :malformed}
    end
  end

  defp reply(state, frame), do: :gen_tcp.send(state.socket, Encap.encode(frame))

  defp arm_inactivity(state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    timer = Process.send_after(self(), :inactivity_timeout, state.config.inactivity_timeout)
    %{state | timer: timer}
  end
end
