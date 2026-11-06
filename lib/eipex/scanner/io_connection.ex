defmodule Eipex.Scanner.IOConnection do
  @moduledoc """
  Scanner-side class 1 (cyclic implicit I/O) connection: owns its own UDP
  socket, opens the connection with a blocking Forward Open transaction in
  `init/1`, produces O->T data on the configured RPI (with optional run/idle
  header), and consumes T->O data with sequence checks and a watchdog.

  Notifies `:owner` with:

    * `{:eipex_io, pid, :data, binary}` — on the first packet and whenever
      the payload changes (identical consecutive payloads are not repeated).
    * `{:eipex_io, pid, :run_idle, :run | :idle}` — on a run/idle transition.
    * `{:eipex_io, pid, :timeout}` — the watchdog expired; the connection is
      best-effort closed on the target and the process stops.
    * `{:eipex_io, pid, :closed}` — `close/1` was called.
  """

  @behaviour :gen_statem

  alias Eipex.CIP.ConnectionManager
  alias Eipex.IO

  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  @spec set_output(pid(), binary()) :: :ok | {:error, :size_mismatch}
  def set_output(pid, data), do: :gen_statem.call(pid, {:set_output, data})

  @doc """
  Forward Closes the connection and stops the statem, returning only once
  the process has actually exited (a monitor, not just the call reply,
  since `:gen_statem` sends call replies before running `terminate/3`).
  """
  @spec close(pid()) :: :ok
  def close(pid) do
    ref = Process.monitor(pid)
    reply = :gen_statem.call(pid, :close)

    receive do
      {:DOWN, ^ref, :process, ^pid, _reason} -> reply
    end
  end

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(args) do
    o2t = Map.new(args.o_to_t)
    t2o = Map.new(args.t_to_o)

    if (o2t[:type] || :point_to_point) == :multicast do
      {:stop, :o2t_multicast_unsupported}
    else
      open(args, o2t, t2o)
    end
  end

  defp open(args, o2t, t2o) do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: true])
    {:ok, udp_port} = :inet.port(socket)

    path_segments =
      [{:class, 0x04}] ++
        case args[:config] do
          nil -> []
          config -> [{:instance, Keyword.fetch!(config, :assembly)}]
        end ++
        [{:connection_point, o2t.assembly}, {:connection_point, t2o.assembly}]

    params = %{
      o2t_size: IO.wire_size(o2t.size, o2t[:run_idle] || false),
      t2o_size: IO.wire_size(t2o.size, t2o[:run_idle] || false),
      o2t_rpi: o2t.rpi,
      t2o_rpi: t2o.rpi,
      o2t_type: :point_to_point,
      t2o_type: t2o[:type] || :point_to_point,
      timeout_multiplier: args[:timeout_multiplier] || 2,
      path_segments: path_segments
    }

    case Eipex.Scanner.io_forward_open(args.scanner, params, udp_port) do
      {:ok, fo, response, sockaddrs} ->
        {:ok, reply} = ConnectionManager.decode_forward_open_reply(response.data)

        {:ok, host} = Eipex.Scanner.host(args.scanner)
        peer = resolve_peer(sockaddrs, host)
        triad = {fo.connection_serial, fo.originator_vendor_id, fo.originator_serial}

        case join_multicast(t2o, sockaddrs) do
          {:ok, mcast_socket} ->
            data = %{
              socket: socket,
              mcast_socket: mcast_socket,
              owner: args.owner,
              scanner: args.scanner,
              o2t_id: reply.o2t_connection_id,
              t2o_id: reply.t2o_connection_id,
              triad: triad,
              path: fo.connection_path,
              peer: peer,
              o2t_run_idle: o2t[:run_idle] || false,
              t2o_run_idle: t2o[:run_idle] || false,
              o2t_size: o2t.size,
              t2o_size: t2o.size,
              output: :binary.copy(<<0>>, o2t.size),
              produce_ms: IO.rpi_ms(o2t.rpi),
              watchdog_ms:
                IO.rpi_ms(t2o.rpi) * ConnectionManager.timeout_factor(params.timeout_multiplier),
              prod_seq32: 0,
              prod_seq16: 0,
              last_seq32: nil,
              last_data: nil,
              run_state: nil
            }

            {:ok, :running, data,
             [
               {{:timeout, :produce}, data.produce_ms, :produce},
               {{:timeout, :watchdog}, data.watchdog_ms, :watchdog}
             ]}

          {:error, reason} ->
            # the target accepted the connection; release it before giving up
            _ = forward_close(%{scanner: args.scanner, triad: triad, path: fo.connection_path})
            :gen_udp.close(socket)
            {:stop, reason}
        end

      {:error, reason} ->
        :gen_udp.close(socket)
        {:stop, reason}
    end
  end

  # A multicast T->O connection consumes from the group the target announced
  # in its reply's sockaddr_t2o, on a socket bound to the group address (so
  # it never intercepts unicast traffic aimed at the shared port).
  defp join_multicast(%{type: :multicast} = t2o, sockaddrs) do
    case for {:sockaddr_t2o, sa} <- sockaddrs, do: sa do
      [%{ip: {first, _, _, _} = group, port: port} | _] when first in 224..239 ->
        :gen_udp.open(port, [
          :binary,
          active: true,
          reuseaddr: true,
          ip: group,
          add_membership: {group, t2o[:interface] || {0, 0, 0, 0}}
        ])

      _ ->
        {:error, :no_multicast_sockaddr}
    end
  end

  defp join_multicast(_t2o, _sockaddrs), do: {:ok, nil}

  @impl true
  def handle_event({:call, from}, {:set_output, output}, :running, %{o2t_size: size} = data)
      when byte_size(output) == size do
    {:keep_state, %{data | output: output}, [{:reply, from, :ok}]}
  end

  def handle_event({:call, from}, {:set_output, _output}, :running, data) do
    {:keep_state, data, [{:reply, from, {:error, :size_mismatch}}]}
  end

  def handle_event({:call, from}, :close, :running, data) do
    _ = forward_close(data)
    notify(data, :closed)
    {:stop_and_reply, :normal, [{:reply, from, :ok}], data}
  end

  def handle_event(
        :info,
        {:udp, socket, _ip, _port, datagram},
        :running,
        %{socket: socket} = data
      ) do
    consume(datagram, data)
  end

  def handle_event(
        :info,
        {:udp, socket, _ip, _port, datagram},
        :running,
        %{mcast_socket: socket} = data
      ) do
    consume(datagram, data)
  end

  def handle_event({:timeout, :produce}, :produce, :running, data) do
    seq32 = IO.next_seq32(data.prod_seq32)
    seq16 = IO.next_seq16(data.prod_seq16)
    run_idle = if data.o2t_run_idle, do: :run, else: nil
    packet = IO.encode_packet(data.o2t_id, seq32, seq16, run_idle, data.output)
    {ip, port} = data.peer
    :gen_udp.send(data.socket, ip, port, packet)

    {:keep_state, %{data | prod_seq32: seq32, prod_seq16: seq16},
     [{{:timeout, :produce}, data.produce_ms, :produce}]}
  end

  def handle_event({:timeout, :watchdog}, :watchdog, :running, data) do
    notify(data, :timeout)
    _ = forward_close(data)
    {:stop, :normal, data}
  end

  def handle_event(_type, _event, _state, data), do: {:keep_state, data}

  @impl true
  def terminate(_reason, _state, data) do
    :gen_udp.close(data.socket)
    if data.mcast_socket, do: :gen_udp.close(data.mcast_socket)
    :ok
  end

  # -- Internal helpers ----------------------------------------------------------

  defp consume(datagram, data) do
    case IO.decode_packet(datagram, data.t2o_run_idle) do
      {:ok, %{conn_id: conn_id, seq32: seq32, run: run, data: payload}}
      when conn_id == data.t2o_id and byte_size(payload) == data.t2o_size ->
        cond do
          not is_nil(data.last_seq32) and not IO.seq_newer?(seq32, data.last_seq32) ->
            {:keep_state, data}

          true ->
            data = notify_on_data_change(data, payload)
            data = notify_on_run_idle_change(data, run)

            {:keep_state, %{data | last_seq32: seq32},
             [{{:timeout, :watchdog}, data.watchdog_ms, :watchdog}]}
        end

      _ ->
        {:keep_state, data}
    end
  end

  defp notify_on_data_change(%{last_data: payload} = data, payload), do: data

  defp notify_on_data_change(data, payload) do
    notify(data, {:data, payload})
    %{data | last_data: payload}
  end

  defp notify_on_run_idle_change(data, nil), do: data
  defp notify_on_run_idle_change(%{run_state: mode} = data, mode), do: data

  defp notify_on_run_idle_change(data, mode) do
    notify(data, {:run_idle, mode})
    %{data | run_state: mode}
  end

  defp notify(data, {tag, value}), do: send(data.owner, {:eipex_io, self(), tag, value})
  defp notify(data, tag), do: send(data.owner, {:eipex_io, self(), tag})

  defp forward_close(data) do
    try do
      Eipex.Scanner.io_forward_close(data.scanner, data.triad, data.path)
    catch
      :exit, _ -> :ok
    end
  end

  defp resolve_peer(sockaddrs, host) do
    case for {:sockaddr_o2t, sa} <- sockaddrs, do: sa do
      [%{ip: {0, 0, 0, 0}, port: port} | _] -> {host, port}
      [%{ip: ip, port: port} | _] -> {ip, port}
      [] -> {host, 2222}
    end
  end
end
