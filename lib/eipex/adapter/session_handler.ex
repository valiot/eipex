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
       closing: false,
       conn_replies: %{}
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

    if state.closing do
      {:stop, :normal, state}
    else
      case :inet.setopts(socket, active: :once) do
        :ok -> {:noreply, arm_inactivity(state)}
        # the peer may have RST'd the connection between the read and here
        {:error, _} -> {:stop, :normal, state}
      end
    end
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state), do: {:stop, :normal, state}
  def handle_info({:tcp_error, socket, _}, %{socket: socket} = state), do: {:stop, :normal, state}

  def handle_info(:inactivity_timeout, state) do
    :gen_tcp.close(state.socket)
    {:stop, {:shutdown, :inactivity_timeout}, state}
  end

  def handle_info({:connection_closed, o2t_id}, state) do
    {:noreply, %{state | conn_replies: Map.delete(state.conn_replies, o2t_id)}}
  end

  # -- Frame handling ------------------------------------------------------------

  defp drain(%{closing: true} = state), do: state

  defp drain(state) do
    case Encap.decode(state.buffer) do
      {:ok, frame, rest} -> %{state | buffer: rest} |> handle_frame(frame) |> drain()
      :partial -> state
    end
  end

  defp handle_frame(state, %Encap{command: :register_session} = frame) do
    cond do
      not is_nil(state.session_handle) ->
        reply(state, %Encap{frame | status: 0x0001})
        state

      not match?(<<1::16-little, 0::16-little>>, frame.data) ->
        reply(state, %Encap{frame | status: 0x0069, data: <<1::16-little, 0::16-little>>})
        state

      true ->
        handle = :erlang.unique_integer([:positive]) |> rem(0xFFFF_FFFE) |> Kernel.+(1)
        reply(state, %Encap{frame | session_handle: handle})
        %{state | session_handle: handle}
    end
  end

  defp handle_frame(state, %Encap{command: :unregister_session}) do
    :gen_tcp.close(state.socket)
    # no reply is defined for unregister; `closing: true` drives the stop
    # once the current packet finishes draining, back in handle_info/2
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

  defp handle_frame(state, %Encap{command: :send_unit_data, session_handle: handle} = frame) do
    cond do
      is_nil(state.session_handle) or handle != state.session_handle ->
        reply(state, %Encap{frame | status: 0x0064, data: <<>>})
        state

      true ->
        case unit_payload(frame) do
          {:ok, conn_id, seq, mr} ->
            serve_connected(state, conn_id, seq, mr)

          {:error, _} ->
            reply(state, %Encap{frame | status: 0x0003, data: <<>>})
            state
        end
    end
  end

  # catch-all: any remaining/unknown encapsulation command is invalid
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

  defp unit_payload(frame) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [{:connected_address, conn_id}] <-
           for({:connected_address, _} = i <- items, do: i),
         [{:connected_data, <<seq::16-little, mr::binary>>}] <-
           for({:connected_data, _} = i <- items, do: i) do
      {:ok, conn_id, seq, mr}
    else
      _ -> {:error, :malformed}
    end
  end

  defp serve_connected(state, conn_id, seq, mr) do
    case Eipex.Adapter.ConnectionTable.lookup_o2t(state.config.connections, conn_id) do
      {:ok, %{session: session, t2o_connection_id: t2o_id}} when session == self() ->
        case state.conn_replies do
          %{^conn_id => {^seq, cached}} ->
            reply(state, cached)
            state

          _ ->
            response = MessageRouter.dispatch(state.config, mr)

            reply_frame = %Encap{
              Encap.send_unit_data(
                state.session_handle,
                CPF.encode([
                  {:connected_address, t2o_id},
                  {:connected_data, <<seq::16-little, response::binary>>}
                ])
              )
              | sender_context: <<0::64>>
            }

            reply(state, reply_frame)
            %{state | conn_replies: Map.put(state.conn_replies, conn_id, {seq, reply_frame})}
        end

      _unknown_or_foreign ->
        # no reply is routable for an unknown/foreign connection: drop
        state
    end
  end

  defp reply(state, frame), do: :gen_tcp.send(state.socket, Encap.encode(frame))

  defp arm_inactivity(state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    timer = Process.send_after(self(), :inactivity_timeout, state.config.inactivity_timeout)
    %{state | timer: timer}
  end
end
