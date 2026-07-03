defmodule Eipex.Scanner do
  @moduledoc """
  EtherNet/IP scanner (originator) session for explicit messaging.

  One process per target device: owns the TCP connection to port 44818,
  registers the encapsulation session, and serializes UCMM requests.
  There is no automatic reconnection: when the connection drops, the
  process exits `{:shutdown, :connection_lost}` and the owning
  application decides whether and when to retry.
  """

  use GenServer

  alias Eipex.{CPF, Encap}
  alias Eipex.CIP.{ConnectionManager, MessageRouter}

  @default_port 44_818
  @default_timeout 5_000
  @default_keepalive 60_000

  defmodule State do
    @moduledoc false
    defstruct socket: nil,
              session_handle: nil,
              buffer: <<>>,
              pending: nil,
              queue: :queue.new(),
              context_counter: 0,
              route_path: :none,
              keepalive: nil,
              timeout: nil
  end

  # -- Public API --------------------------------------------------------------

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @spec close(GenServer.server()) :: :ok
  def close(server), do: GenServer.call(server, :close)

  @type response :: %{
          service: byte(),
          status: byte(),
          status_name: atom(),
          extended: [non_neg_integer()],
          data: binary()
        }

  @spec generic_message(GenServer.server(), keyword()) ::
          {:ok, response()} | {:error, term()}
  def generic_message(server, opts) do
    GenServer.call(server, {:request, opts}, :infinity)
  end

  @spec get_attribute(
          GenServer.server(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          keyword()
        ) ::
          {:ok, binary()} | {:error, term()}
  def get_attribute(server, class, instance, attribute, opts \\ []) do
    opts =
      Keyword.merge(opts, service: 0x0E, class: class, instance: instance, attribute: attribute)

    server |> generic_message(opts) |> unwrap_cip()
  end

  @spec get_attributes_all(GenServer.server(), non_neg_integer(), non_neg_integer(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def get_attributes_all(server, class, instance, opts \\ []) do
    opts = Keyword.merge(opts, service: 0x01, class: class, instance: instance)
    server |> generic_message(opts) |> unwrap_cip()
  end

  @spec set_attribute(
          GenServer.server(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          binary(),
          keyword()
        ) ::
          :ok | {:error, term()}
  def set_attribute(server, class, instance, attribute, data, opts \\ []) do
    opts =
      Keyword.merge(opts,
        service: 0x10,
        class: class,
        instance: instance,
        attribute: attribute,
        data: data
      )

    case server |> generic_message(opts) |> unwrap_cip() do
      {:ok, _data} -> :ok
      error -> error
    end
  end

  # -- GenServer ---------------------------------------------------------------

  @impl true
  def init(opts) do
    host = opts |> Keyword.fetch!(:host) |> normalize_host()
    port = Keyword.get(opts, :port, @default_port)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    socket_opts = [:binary, packet: :raw, active: false, keepalive: true]

    with {:ok, socket} <- :gen_tcp.connect(host, port, socket_opts, timeout),
         {:ok, handle} <- register_session(socket, timeout) do
      :ok = :inet.setopts(socket, active: :once)

      {:ok,
       %State{
         socket: socket,
         session_handle: handle,
         route_path: opts |> Keyword.get(:route_path, :none) |> normalize_route(),
         keepalive: Keyword.get(opts, :keepalive, @default_keepalive),
         timeout: timeout
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:request, opts}, from, state) do
    case build_request(opts, state) do
      {:ok, mr} ->
        timeout = Keyword.get(opts, :timeout, state.timeout)

        if state.pending do
          {:noreply, %{state | queue: :queue.in({from, mr, timeout}, state.queue)}}
        else
          {:noreply, send_request(state, from, mr, timeout)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:close, _from, state) do
    _ = :gen_tcp.send(state.socket, Encap.encode(Encap.unregister_session(state.session_handle)))
    :gen_tcp.close(state.socket)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:tcp, socket, data}, %State{socket: socket} = state) do
    state = drain_frames(%{state | buffer: state.buffer <> data})
    :ok = :inet.setopts(socket, active: :once)
    {:noreply, state}
  end

  def handle_info({:request_timeout, context}, state) do
    case state.pending do
      {from, ^context, _timer} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, next_request(%{state | pending: nil})}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:tcp_closed, socket}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, state}
  end

  def handle_info({:tcp_error, socket, _reason}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, state}
  end

  # -- Session registration (passive mode, inside init) -------------------------

  defp register_session(socket, timeout) do
    with :ok <- :gen_tcp.send(socket, Encap.encode(Encap.register_session())),
         {:ok, %Encap{command: :register_session, status: 0, session_handle: handle}} <-
           recv_frame(socket, <<>>, timeout) do
      {:ok, handle}
    else
      {:ok, %Encap{status: status}} -> {:error, {:encap, Encap.status_name(status)}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp recv_frame(socket, buffer, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        case Encap.decode(buffer <> data) do
          {:ok, frame, _rest} -> {:ok, frame}
          :partial -> recv_frame(socket, buffer <> data, timeout)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # -- Option normalization ------------------------------------------------------

  defp unwrap_cip({:ok, %{status_name: :success, data: data}}), do: {:ok, data}

  defp unwrap_cip({:ok, %{status_name: name, extended: extended}}),
    do: {:error, {:cip, name, extended}}

  defp unwrap_cip({:error, _} = error), do: error

  defp normalize_host(host) when is_binary(host), do: String.to_charlist(host)
  defp normalize_host(host), do: host

  defp normalize_route(:none), do: :none
  defp normalize_route(backplane: slot), do: [{:port, 1, slot}]
  defp normalize_route(segments) when is_list(segments), do: segments

  # -- Request pipeline ----------------------------------------------------------

  defp build_request(opts, state) do
    with {:ok, service} <- Keyword.fetch(opts, :service),
         {:ok, path} <- request_path(opts) do
      mr = MessageRouter.encode_request(service, path, Keyword.get(opts, :data, <<>>))

      case request_route(opts, state) do
        :none -> {:ok, mr}
        route -> {:ok, ConnectionManager.encode_unconnected_send(mr, route, [])}
      end
    else
      :error -> {:error, :missing_service}
      {:error, _} = error -> error
    end
  end

  defp request_route(opts, state) do
    case Keyword.fetch(opts, :route_path) do
      {:ok, route} -> normalize_route(route)
      :error -> state.route_path
    end
  end

  defp request_path(opts) do
    cond do
      path = opts[:path] ->
        {:ok, path}

      name = opts[:symbolic] ->
        {:ok, [{:symbolic, name}]}

      class = opts[:class] ->
        base = [{:class, class}, {:instance, Keyword.get(opts, :instance, 1)}]

        case opts[:attribute] do
          nil -> {:ok, base}
          attribute -> {:ok, base ++ [{:attribute, attribute}]}
        end

      true ->
        {:error, :missing_path}
    end
  end

  defp send_request(state, from, mr, timeout) do
    context = <<state.context_counter::64-little>>
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}])

    frame = %Encap{
      Encap.send_rr_data(state.session_handle, cpf)
      | sender_context: context
    }

    :ok = :gen_tcp.send(state.socket, Encap.encode(frame))
    timer = Process.send_after(self(), {:request_timeout, context}, timeout)

    %{state | pending: {from, context, timer}, context_counter: state.context_counter + 1}
  end

  defp next_request(%State{pending: nil} = state) do
    case :queue.out(state.queue) do
      {{:value, {from, mr, timeout}}, queue} ->
        send_request(%{state | queue: queue}, from, mr, timeout)

      {:empty, _} ->
        state
    end
  end

  # -- Inbound frames --------------------------------------------------------------

  defp drain_frames(state) do
    case Encap.decode(state.buffer) do
      {:ok, frame, rest} ->
        %{state | buffer: rest} |> handle_frame(frame) |> drain_frames()

      :partial ->
        state
    end
  end

  defp handle_frame(
         %State{pending: {from, context, timer}} = state,
         %Encap{command: :send_rr_data, sender_context: context} = frame
       ) do
    Process.cancel_timer(timer)
    GenServer.reply(from, decode_reply(frame))
    next_request(%{state | pending: nil})
  end

  defp handle_frame(state, %Encap{}), do: state

  defp decode_reply(%Encap{status: 0} = frame) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [mr | _] <- for({:unconnected_data, d} <- items, do: d),
         {:ok, response} <- MessageRouter.decode_response(mr) do
      {:ok, response}
    else
      [] -> {:error, :no_data_item}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_reply(%Encap{status: status}) do
    {:error, {:encap, Encap.status_name(status)}}
  end
end
