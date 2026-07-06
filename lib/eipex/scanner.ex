defmodule Eipex.Scanner do
  @moduledoc """
  EtherNet/IP scanner (originator) session for explicit messaging.

  One process per target device: owns the TCP connection to port 44818,
  registers the encapsulation session, and serializes UCMM requests.
  There is no automatic reconnection: when the connection drops, the
  process exits `{:shutdown, :connection_lost}` and the owning
  application decides whether and when to retry.

  Also supports connected (class 3) messaging: `forward_open/2` and
  `forward_close/1` establish and tear down a single connection per
  session, after which `generic_message/2` can be routed over it with
  `connected: true`.
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
              host: nil,
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

  @doc """
  Opens a class 3 (explicit messaging) connection to the target.

  Only one connection per scanner session is supported; a second call
  while one is open (or already queued behind one) returns
  `{:error, :already_connected}`.

  ## Options

    * `:variant` - `:large` (default) or `:standard`. `:large` sends a
      Large Forward Open (0x5B, up to 65535-byte connection sizes); if the
      target rejects it with a CIP error, the scanner automatically falls
      back to a standard Forward Open (0x54) once. Passing `:standard`
      skips the large attempt. Any other value returns
      `{:error, {:invalid_request, :variant}}` without touching the
      network.

  On success, returns `{:ok, conn_info}` where `conn_info` is a map with
  `:o2t_connection_id`, `:t2o_connection_id`, `:connection_serial`,
  `:size` and `:variant` — enough to correlate the connection, not the
  internal sequence counter or encoded path.

  Note on timeouts: the request is built with a 10-tick, 10ms-per-tick
  CIP timeout (~10s of wire budget for the target to answer), while the
  scanner's own local wait defaults to 5s (`:timeout` at `start_link/1`,
  overridable per session but not per call). A slow target can therefore
  make this call return `{:error, :timeout}` locally while still
  registering the connection on the target side; a subsequent
  `forward_open/2` in that situation will observe `:already_connected`
  from the target and fail, and only `forward_close/1` (or a fresh
  session) will clear it.
  """
  @spec forward_open(GenServer.server(), keyword()) :: {:ok, map()} | {:error, term()}
  def forward_open(server, opts \\ []) do
    GenServer.call(server, {:forward_open, opts}, :infinity)
  end

  @doc """
  Closes the scanner's current connection, if any.

  Returns `:error, :no_connection` when no connection is open. A target
  that answers with CIP error 0x01/extended 0x0107
  (`:target_connection_not_found` — it already timed out or dropped the
  connection, e.g. after its own inactivity watchdog fired) is treated as
  a successful close: this call still returns `:ok` and the scanner
  clears its local connection state, since there is nothing left to close
  on either side.
  """
  @spec forward_close(GenServer.server()) :: :ok | {:error, term()}
  def forward_close(server), do: GenServer.call(server, :forward_close, :infinity)

  @doc """
  Opens a class 1 (cyclic implicit I/O) connection to the target.

  Starts (and links) an `Eipex.Scanner.IOConnection`, which owns its own UDP
  socket and blocks in its `init/1` for the Forward Open transaction before
  returning. See `Eipex.Scanner.IOConnection` for the options and the
  notifications sent to `:owner`.

  On a Forward Open rejection the statem's `init/1` stops with `{:stop,
  reason}`; since `start_link` links the calling process, trapping exits for
  the duration of the call keeps that failure a plain `{:error, reason}`
  return here instead of taking the caller down too (mirrors OTP's own
  `start_link` guidance for callers that are not supervisors).
  """
  @spec open_io(GenServer.server(), keyword()) :: {:ok, pid()} | {:error, term()}
  def open_io(server, opts) do
    args = opts |> Map.new() |> Map.put(:scanner, server)
    previous_trap = Process.flag(:trap_exit, true)

    try do
      Eipex.Scanner.IOConnection.start_link(args)
    after
      Process.flag(:trap_exit, previous_trap)
    end
  end

  @doc """
  Returns the resolved IPv4 address of the target, as connected to at
  `start_link/1` time. Used by `Eipex.Scanner.IOConnection` to resolve
  `{0, 0, 0, 0}` sockaddrs to a concrete peer.
  """
  @spec host(GenServer.server()) :: {:ok, :inet.ip4_address()}
  def host(server), do: GenServer.call(server, :host)

  @doc false
  @spec io_forward_open(GenServer.server(), map(), :inet.port_number()) ::
          {:ok, ConnectionManager.ForwardOpen.t(), response(), [CPF.item()]} | {:error, term()}
  def io_forward_open(server, params, udp_port),
    do: GenServer.call(server, {:io_forward_open, params, udp_port}, :infinity)

  @doc false
  @spec io_forward_close(
          GenServer.server(),
          {non_neg_integer(), non_neg_integer(), non_neg_integer()},
          binary()
        ) ::
          :ok | {:error, term()}
  def io_forward_close(server, triad, path),
    do: GenServer.call(server, {:io_forward_close, triad, path}, :infinity)

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

    with {:ok, resolved_host} <- :inet.getaddr(host, :inet),
         {:ok, socket} <- :gen_tcp.connect(resolved_host, port, socket_opts, timeout),
         {:ok, handle, rest} <- register_session(socket, timeout) do
      :ok = :inet.setopts(socket, active: :once)

      state = %State{
        socket: socket,
        session_handle: handle,
        buffer: rest,
        route_path: opts |> Keyword.get(:route_path, :none) |> normalize_route(),
        keepalive: Keyword.get(opts, :keepalive, @default_keepalive),
        timeout: timeout,
        host: resolved_host,
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
    built =
      try do
        if Keyword.get(opts, :connected, false) do
          :connected
        else
          build_request(opts, state)
        end
      rescue
        exception -> {:invalid, Exception.message(exception)}
      end

    case built do
      :connected ->
        connected_request(opts, from, state)

      {:invalid, message} ->
        {:reply, {:error, {:invalid_request, message}}, state}

      {:ok, mr} ->
        dispatch_request(state, from, mr, Keyword.get(opts, :timeout, state.timeout), :request)

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:forward_open, _opts}, _from, %State{connection: conn} = state)
      when not is_nil(conn) do
    {:reply, {:error, :already_connected}, state}
  end

  def handle_call({:forward_open, opts}, from, state) do
    variant = Keyword.get(opts, :variant, :large)

    if variant in [:large, :standard] do
      {fo, state} = build_forward_open(state, variant)
      mr = ConnectionManager.encode_forward_open(fo, variant)
      meta = %{fo: fo, variant: variant, fallback: variant == :large}
      dispatch_request(state, from, mr, state.timeout, {:forward_open, meta})
    else
      {:reply, {:error, {:invalid_request, :variant}}, state}
    end
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
  def handle_call(:host, _from, state) do
    {:reply, {:ok, state.host}, state}
  end

  def handle_call({:io_forward_open, params, udp_port}, from, state) do
    {fo, state} = build_io_forward_open(state, params)
    mr = ConnectionManager.encode_forward_open(fo, :standard)
    extra_cpf = [{:sockaddr_t2o, %{ip: {0, 0, 0, 0}, port: udp_port}}]
    dispatch_request(state, from, {:ucmm, mr, extra_cpf}, state.timeout, {:io_reply, fo})
  end

  def handle_call({:io_forward_close, {serial, vendor, orig_serial}, path}, from, state) do
    triad = %{
      connection_serial: serial,
      originator_vendor_id: vendor,
      originator_serial: orig_serial
    }

    mr = ConnectionManager.encode_forward_close(triad, path, [])
    dispatch_request(state, from, mr, state.timeout, :io_close)
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
      built =
        try do
          mr = MessageRouter.encode_request(service, path, Keyword.get(opts, :data, <<>>))
          {:ok, mr}
        rescue
          exception -> {:invalid, Exception.message(exception)}
        end

      case built do
        {:ok, mr} ->
          timeout = Keyword.get(opts, :timeout, state.timeout)
          dispatch_request(state, from, {:unit, mr}, timeout, :connected)

        {:invalid, message} ->
          {:reply, {:error, {:invalid_request, message}}, state}
      end
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

  defp send_request(%State{connection: conn} = state, from, _mr, _timeout, {:forward_open, _meta})
       when not is_nil(conn) do
    GenServer.reply(from, {:error, :already_connected})
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
    send_request(state, from, {:ucmm, mr, []}, timeout, kind)
  end

  defp send_request(state, from, {:ucmm, mr, extra_cpf}, timeout, kind) do
    context = <<state.context_counter::64-little>>
    cpf = CPF.encode([:null_address, {:unconnected_data, mr}] ++ extra_cpf)

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

  defp settle_reply(:request, {:ok, response, _sockaddrs}, from, state) do
    GenServer.reply(from, {:ok, response})
    next_request(state)
  end

  defp settle_reply(:request, {:error, _} = error, from, state) do
    GenServer.reply(from, error)
    next_request(state)
  end

  defp settle_reply({:forward_open, meta}, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success, data: data}, _sockaddrs} ->
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

      {:ok, %{status_name: _name, extended: _extended}, _sockaddrs} when meta.fallback ->
        {fo, state} = build_forward_open(state, :standard)
        mr = ConnectionManager.encode_forward_open(fo, :standard)
        meta = %{fo: fo, variant: :standard, fallback: false}

        # send_request returns {:ok, state} | {:lost, state} — propagate the tag
        # verbatim (on :lost it already replied {:error, :connection_lost} to from)
        send_request(state, from, mr, state.timeout, {:forward_open, meta})

      {:ok, %{status_name: name, extended: extended}, _sockaddrs} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end

  defp settle_reply(:forward_close, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success}, _sockaddrs} ->
        GenServer.reply(from, :ok)
        next_request(%{state | connection: nil})

      # the target has already timed out/dropped this connection: treat the
      # close as having succeeded rather than wedging the scanner permanently
      # in :already_connected (real targets idle-timeout class 3 connections)
      {:ok, %{status_name: _name, extended: [0x0107]}, _sockaddrs} ->
        GenServer.reply(from, :ok)
        next_request(%{state | connection: nil})

      {:ok, %{status_name: name, extended: extended}, _sockaddrs} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end

  defp settle_reply({:io_reply, fo}, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success} = response, sockaddrs} ->
        GenServer.reply(from, {:ok, fo, response, sockaddrs})
        next_request(state)

      {:ok, %{status_name: name, extended: extended}, _sockaddrs} ->
        GenServer.reply(from, {:error, {:cip, name, extended}})
        next_request(state)

      {:error, _} = error ->
        GenServer.reply(from, error)
        next_request(state)
    end
  end

  defp settle_reply(:io_close, reply, from, state) do
    case reply do
      {:ok, %{status_name: :success}, _sockaddrs} ->
        GenServer.reply(from, :ok)
        next_request(state)

      # mirrors :forward_close's 0x0107 treatment: an already-dropped
      # connection on the target counts as a successful close here too
      {:ok, %{status_name: _name, extended: [0x0107]}, _sockaddrs} ->
        GenServer.reply(from, :ok)
        next_request(state)

      {:ok, %{status_name: name, extended: extended}, _sockaddrs} ->
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
      sockaddrs = for {tag, _sa} = item <- items, tag in [:sockaddr_o2t, :sockaddr_t2o], do: item
      {:ok, response, sockaddrs}
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

  # -- Class 1 (cyclic implicit I/O) Forward Open --------------------------------

  defp build_io_forward_open(state, params) do
    serial = state.connection_serial_counter

    fo = %ConnectionManager.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: Bitwise.band(:erlang.unique_integer([:positive]), 0xFFFF_FFFF),
      connection_serial: serial,
      originator_vendor_id: state.vendor_id,
      originator_serial: state.serial_number,
      timeout_multiplier: params.timeout_multiplier,
      o2t_rpi: params.o2t_rpi,
      o2t_params: io_connection_params(params.o2t_size),
      t2o_rpi: params.t2o_rpi,
      t2o_params: io_connection_params(params.t2o_size),
      transport: %{direction: :server, trigger: :cyclic, class: 1},
      connection_path: Path.encode(params.path_segments)
    }

    {fo, %{state | connection_serial_counter: serial + 1}}
  end

  defp io_connection_params(size),
    do: %{
      owner: :exclusive,
      type: :point_to_point,
      priority: :low,
      size_type: :fixed,
      size: size
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
