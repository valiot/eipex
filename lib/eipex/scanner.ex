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
  alias Eipex.CIP.{ConnectionManager, MessageRouter, Path}

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
              context_counter: 1,
              route_path: :none,
              keepalive: nil,
              timeout: nil,
              vendor_id: 0xFFFF,
              serial_number: 0,
              connection_serial_counter: 1,
              connection: nil
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

  defdelegate discover(opts \\ []), to: Eipex.Scanner.Discovery

  @spec forward_open(GenServer.server(), keyword()) :: {:ok, map()} | {:error, term()}
  def forward_open(server, opts \\ []) do
    GenServer.call(server, {:forward_open, opts}, :infinity)
  end

  @spec forward_close(GenServer.server()) :: :ok | {:error, term()}
  def forward_close(server), do: GenServer.call(server, :forward_close, :infinity)

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

    socket_opts = [
      :binary,
      packet: :raw,
      active: false,
      keepalive: true,
      send_timeout: timeout,
      send_timeout_close: true
    ]

    with {:ok, socket} <- :gen_tcp.connect(host, port, socket_opts, timeout),
         {:ok, handle, rest} <- register_session(socket, timeout) do
      :ok = :inet.setopts(socket, active: :once)

      state = %State{
        socket: socket,
        session_handle: handle,
        buffer: rest,
        route_path: opts |> Keyword.get(:route_path, :none) |> normalize_route(),
        keepalive: Keyword.get(opts, :keepalive, @default_keepalive),
        timeout: timeout,
        vendor_id: Keyword.get(opts, :vendor_id, 0xFFFF),
        serial_number:
          Keyword.get_lazy(opts, :serial_number, fn ->
            Bitwise.band(:erlang.unique_integer([:positive]), 0xFFFF_FFFF)
          end)
      }

      {:ok, schedule_keepalive(state)}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:request, opts}, from, state) do
    if Keyword.get(opts, :connected, false) do
      connected_request(opts, from, state)
    else
      case build_request(opts, state) do
        {:ok, mr} ->
          timeout = Keyword.get(opts, :timeout, state.timeout)
          dispatch_request(state, from, mr, timeout, :request)

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  rescue
    exception ->
      {:reply, {:error, {:invalid_request, Exception.message(exception)}}, state}
  end

  @impl true
  def handle_call({:forward_open, _opts}, _from, %State{connection: conn} = state)
      when not is_nil(conn) do
    {:reply, {:error, :already_connected}, state}
  end

  def handle_call({:forward_open, opts}, from, state) do
    variant = Keyword.get(opts, :variant, :large)
    {fo, state} = build_forward_open(state, variant)
    mr = ConnectionManager.encode_forward_open(fo, variant)
    meta = %{fo: fo, variant: variant, fallback: variant == :large}
    dispatch_request(state, from, mr, state.timeout, {:forward_open, meta})
  end

  def handle_call(:forward_close, _from, %State{connection: nil} = state) do
    {:reply, {:error, :no_connection}, state}
  end

  def handle_call(:forward_close, from, state) do
    conn = state.connection

    triad = %{
      connection_serial: conn.connection_serial,
      originator_vendor_id: state.vendor_id,
      originator_serial: state.serial_number
    }

    mr = ConnectionManager.encode_forward_close(triad, conn.connection_path, [])
    dispatch_request(state, from, mr, state.timeout, :forward_close)
  end

  @impl true
  def handle_call(:close, _from, state) do
    state = fail_callers(state, {:error, :closed})
    _ = :gen_tcp.send(state.socket, Encap.encode(Encap.unregister_session(state.session_handle)))
    :gen_tcp.close(state.socket)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:tcp, socket, data}, %State{socket: socket} = state) do
    case drain_frames(%{state | buffer: state.buffer <> data}) do
      {:ok, state} ->
        :ok = :inet.setopts(socket, active: :once)
        {:noreply, state}

      {:lost, state} ->
        {:stop, {:shutdown, :connection_lost}, fail_callers(state, {:error, :connection_lost})}
    end
  end

  def handle_info({:request_timeout, context}, state) do
    case state.pending do
      {from, ^context, _timer, _kind} ->
        GenServer.reply(from, {:error, :timeout})

        case next_request(%{state | pending: nil}) do
          {:ok, state} ->
            {:noreply, state}

          {:lost, state} ->
            {:stop, {:shutdown, :connection_lost},
             fail_callers(state, {:error, :connection_lost})}
        end

      _ ->
        {:noreply, state}
    end
  end

  def handle_info(:keepalive, state) do
    _ = :gen_tcp.send(state.socket, Encap.encode(Encap.nop()))
    {:noreply, schedule_keepalive(state)}
  end

  def handle_info({:tcp_closed, socket}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, fail_callers(state, {:error, :connection_lost})}
  end

  def handle_info({:tcp_error, socket, _reason}, %State{socket: socket} = state) do
    {:stop, {:shutdown, :connection_lost}, fail_callers(state, {:error, :connection_lost})}
  end

  # -- Session registration (passive mode, inside init) -------------------------

  defp register_session(socket, timeout) do
    with :ok <- :gen_tcp.send(socket, Encap.encode(Encap.register_session())),
         {:ok, %Encap{command: :register_session, status: 0, session_handle: handle}, rest} <-
           recv_frame(socket, <<>>, timeout) do
      {:ok, handle, rest}
    else
      {:ok, %Encap{command: command, status: 0}, _rest} -> {:error, {:unexpected_reply, command}}
      {:ok, %Encap{status: status}, _rest} -> {:error, {:encap, Encap.status_name(status)}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp recv_frame(socket, buffer, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        case Encap.decode(buffer <> data) do
          {:ok, frame, rest} -> {:ok, frame, rest}
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
        :none ->
          {:ok, mr}

        route ->
          timeout = Keyword.get(opts, :timeout, state.timeout)
          ticks = min(255, ceil(max(timeout, 10_000) / 1024))
          {:ok, ConnectionManager.encode_unconnected_send(mr, route, timeout_ticks: ticks)}
      end
    else
      :error -> {:error, :missing_service}
      {:error, _} = error -> error
    end
  end

  defp connected_request(_opts, _from, %State{connection: nil} = state) do
    {:reply, {:error, :no_connection}, state}
  end

  defp connected_request(opts, from, state) do
    with {:ok, service} <- Keyword.fetch(opts, :service),
         {:ok, path} <- request_path(opts) do
      mr = MessageRouter.encode_request(service, path, Keyword.get(opts, :data, <<>>))
      timeout = Keyword.get(opts, :timeout, state.timeout)
      dispatch_request(state, from, {:unit, mr}, timeout, :connected)
    else
      :error -> {:reply, {:error, :missing_service}, state}
      {:error, _} = error -> {:reply, error, state}
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

  defp dispatch_request(state, from, mr, timeout, kind) do
    if state.pending do
      {:noreply, %{state | queue: :queue.in({from, mr, timeout, kind}, state.queue)}}
    else
      case send_request(state, from, mr, timeout, kind) do
        {:ok, state} ->
          {:noreply, state}

        {:lost, state} ->
          {:stop, {:shutdown, :connection_lost}, fail_callers(state, {:error, :connection_lost})}
      end
    end
  end

  defp send_request(%State{connection: nil} = state, from, {:unit, _mr}, _timeout, :connected) do
    GenServer.reply(from, {:error, :no_connection})
    next_request(state)
  end

  defp send_request(state, from, {:unit, mr}, timeout, :connected) do
    conn = state.connection
    seq = conn.seq

    cpf =
      CPF.encode([
        {:connected_address, conn.o2t_connection_id},
        {:connected_data, <<seq::16-little, mr::binary>>}
      ])

    frame = Encap.send_unit_data(state.session_handle, cpf)

    case :gen_tcp.send(state.socket, Encap.encode(frame)) do
      :ok ->
        timer = Process.send_after(self(), {:request_timeout, {:unit, seq}}, timeout)
        next_seq = if seq >= 0xFFFF, do: 1, else: seq + 1

        {:ok,
         %{
           state
           | pending: {from, {:unit, seq}, timer, {:connected, conn.t2o_connection_id, seq}},
             connection: %{conn | seq: next_seq}
         }}

      {:error, _} ->
        GenServer.reply(from, {:error, :connection_lost})
        {:lost, state}
    end
  end

  defp send_request(state, from, mr, timeout, kind) when is_binary(mr) do
    context = <<state.context_counter::64-little>>
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}])

    frame = %Encap{
      Encap.send_rr_data(state.session_handle, cpf)
      | sender_context: context
    }

    case :gen_tcp.send(state.socket, Encap.encode(frame)) do
      :ok ->
        timer = Process.send_after(self(), {:request_timeout, context}, timeout)

        {:ok,
         %{
           state
           | pending: {from, context, timer, kind},
             context_counter: state.context_counter + 1
         }}

      {:error, _reason} ->
        GenServer.reply(from, {:error, :connection_lost})
        {:lost, state}
    end
  end

  defp next_request(%State{pending: nil} = state) do
    case :queue.out(state.queue) do
      {{:value, {from, mr, timeout, kind}}, queue} ->
        send_request(%{state | queue: queue}, from, mr, timeout, kind)

      {:empty, _} ->
        {:ok, state}
    end
  end

  # -- Inbound frames --------------------------------------------------------------

  defp drain_frames(state) do
    case Encap.decode(state.buffer) do
      {:ok, frame, rest} ->
        case handle_frame(%{state | buffer: rest}, frame) do
          {:ok, state} -> drain_frames(state)
          {:lost, state} -> {:lost, state}
        end

      :partial ->
        {:ok, state}
    end
  end

  defp handle_frame(
         %State{pending: {from, context, timer, kind}} = state,
         %Encap{command: :send_rr_data, sender_context: context} = frame
       ) do
    Process.cancel_timer(timer)
    settle_reply(kind, decode_reply(frame), from, %{state | pending: nil})
  end

  defp handle_frame(
         %State{pending: {from, _ref, timer, {:connected, t2o_id, seq}}} = state,
         %Encap{command: :send_unit_data, status: 0} = frame
       ) do
    with {:ok, cpf} <- Encap.unwrap_cpf(frame),
         {:ok, items} <- CPF.decode(cpf),
         [{:connected_address, ^t2o_id}] <-
           for({:connected_address, _} = i <- items, do: i),
         [{:connected_data, <<^seq::16-little, mr::binary>>}] <-
           for({:connected_data, _} = i <- items, do: i),
         {:ok, response} <- MessageRouter.decode_response(mr) do
      Process.cancel_timer(timer)
      GenServer.reply(from, {:ok, response})
      next_request(%{state | pending: nil})
    else
      _mismatch -> {:ok, state}
    end
  end

  defp handle_frame(state, %Encap{}), do: {:ok, state}

  defp settle_reply(:request, reply, from, state) do
    GenServer.reply(from, reply)
    next_request(state)
  end

  defp settle_reply({:forward_open, meta}, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success, data: data}} ->
        case ConnectionManager.decode_forward_open_reply(data) do
          {:ok, fo_reply} ->
            conn = %{
              o2t_connection_id: fo_reply.o2t_connection_id,
              t2o_connection_id: fo_reply.t2o_connection_id,
              connection_serial: meta.fo.connection_serial,
              connection_path: meta.fo.connection_path,
              size: meta.fo.o2t_params.size,
              variant: meta.variant,
              seq: 1
            }

            GenServer.reply(from, {:ok, Map.drop(conn, [:seq, :connection_path])})
            next_request(%{state | connection: conn})

          {:error, reason} ->
            GenServer.reply(from, {:error, reason})
            next_request(state)
        end

      {:ok, %{status_name: _name, extended: _extended}} when meta.fallback ->
        {fo, state} = build_forward_open(state, :standard)
        mr = ConnectionManager.encode_forward_open(fo, :standard)
        meta = %{fo: fo, variant: :standard, fallback: false}

        # send_request returns {:ok, state} | {:lost, state} — propagate the tag
        # verbatim (on :lost it already replied {:error, :connection_lost} to from)
        send_request(state, from, mr, state.timeout, {:forward_open, meta})

      {:ok, %{status_name: name, extended: extended}} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end

  defp settle_reply(:forward_close, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success}} ->
        GenServer.reply(from, :ok)
        next_request(%{state | connection: nil})

      {:ok, %{status_name: name, extended: extended}} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end

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

  # -- Connected messaging: Forward Open / Forward Close -------------------------

  defp build_forward_open(state, variant) do
    serial = state.connection_serial_counter

    route =
      case state.route_path do
        :none -> []
        segments -> segments
      end

    fo = %ConnectionManager.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: Bitwise.band(:erlang.unique_integer([:positive]), 0xFFFF_FFFF),
      connection_serial: serial,
      originator_vendor_id: state.vendor_id,
      originator_serial: state.serial_number,
      timeout_multiplier: 1,
      o2t_rpi: 10_000_000,
      o2t_params: connection_params(variant),
      t2o_rpi: 10_000_000,
      t2o_params: connection_params(variant),
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(route ++ [class: 0x02, instance: 0x01])
    }

    {fo, %{state | connection_serial_counter: serial + 1}}
  end

  defp connection_params(:large),
    do: %{
      owner: :exclusive,
      type: :point_to_point,
      priority: :low,
      size_type: :variable,
      size: 4002
    }

  defp connection_params(:standard),
    do: %{
      owner: :exclusive,
      type: :point_to_point,
      priority: :low,
      size_type: :variable,
      size: 500
    }

  # -- Keepalive and loss handling ------------------------------------------------

  defp schedule_keepalive(%State{keepalive: :none} = state), do: state

  defp schedule_keepalive(%State{keepalive: interval} = state) when is_integer(interval) do
    Process.send_after(self(), :keepalive, interval)
    state
  end

  defp fail_callers(state, reply) do
    case state.pending do
      {from, _context, timer, _kind} ->
        Process.cancel_timer(timer)
        GenServer.reply(from, reply)

      nil ->
        :ok
    end

    for {from, _mr, _timeout, _kind} <- :queue.to_list(state.queue) do
      GenServer.reply(from, reply)
    end

    %{state | pending: nil, queue: :queue.new()}
  end
end
