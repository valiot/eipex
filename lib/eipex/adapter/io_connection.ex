defmodule Eipex.Adapter.IoConnection do
  @moduledoc """
  One class 1 (cyclic) I/O connection on the adapter side. Consumes O->T
  datagrams (sequence-validated, run/idle tracked, watchdog-guarded) and
  produces T->O datagrams on the RPI from the input assembly — to the
  originator's endpoint, or to the configured multicast group when the
  connection was opened with a multicast T->O. Exclusive owner. Dies on
  watchdog timeout or Forward Close; the ConnectionTable monitors this
  process, so death always releases the triad.
  """

  @behaviour :gen_statem

  alias Eipex.Adapter.{AssemblyStore, ConnectionTable, UDP}
  alias Eipex.IO

  def child_spec(args) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [args]}, restart: :temporary}
  end

  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  def activate(pid, o2t_id, peer), do: :gen_statem.cast(pid, {:activate, o2t_id, peer})

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(args) do
    {:ok, :waiting,
     Map.merge(args, %{
       o2t_id: nil,
       peer: nil,
       last_seq32: nil,
       run_state: :idle,
       prod_seq32: 0,
       prod_seq16: 0
     })}
  end

  @impl true
  def handle_event(:cast, {:activate, o2t_id, peer}, :waiting, data) do
    data = %{data | o2t_id: o2t_id, peer: peer}
    data.handler.connection_event(conn_info(data), :opened)

    {:next_state, :established, data,
     [
       {{:timeout, :produce}, data.t2o_rpi_ms, :produce},
       {{:timeout, :watchdog}, data.watchdog_ms, :watchdog}
     ]}
  end

  def handle_event(:info, {:io_datagram, datagram, _from}, :established, data) do
    case IO.decode_packet(datagram, data.o2t_run_idle) do
      {:ok, %{conn_id: conn_id, seq32: seq32, run: run, data: payload}}
      when conn_id == data.o2t_id ->
        cond do
          not is_nil(data.last_seq32) and not IO.seq_newer?(seq32, data.last_seq32) ->
            {:keep_state, data}

          byte_size(payload) != data.o2t_size ->
            {:keep_state, data}

          true ->
            :ok = AssemblyStore.write(data.store, data.o2t_assembly, payload)
            _ = data.handler.after_assembly_write(data.o2t_assembly, payload, %{})
            data = track_run_idle(data, run)

            {:keep_state, %{data | last_seq32: seq32},
             [{{:timeout, :watchdog}, data.watchdog_ms, :watchdog}]}
        end

      _ ->
        {:keep_state, data}
    end
  end

  def handle_event({:timeout, :produce}, :produce, :established, data) do
    payload =
      case data.handler.before_assembly_read(data.t2o_assembly, %{}) do
        {:ok, fresh} ->
          case AssemblyStore.write(data.store, data.t2o_assembly, fresh) do
            :ok -> fresh
            {:error, _} -> read_stored(data)
          end

        :keep ->
          read_stored(data)
      end

    seq32 = IO.next_seq32(data.prod_seq32)
    seq16 = IO.next_seq16(data.prod_seq16)
    run_idle = if data.t2o_run_idle, do: :run, else: nil
    packet = IO.encode_packet(data.t2o_id, seq32, seq16, run_idle, payload)
    {ip, port} = data.peer
    UDP.send(data.udp, ip, port, packet)

    {:keep_state, %{data | prod_seq32: seq32, prod_seq16: seq16},
     [{{:timeout, :produce}, data.t2o_rpi_ms, :produce}]}
  end

  def handle_event({:timeout, :watchdog}, :watchdog, :established, data) do
    data.handler.connection_event(conn_info(data), :timeout)
    _ = ConnectionTable.unregister(data.table, data.triad)
    {:stop, :normal, data}
  end

  def handle_event(:info, :close, _state, data) do
    data.handler.connection_event(conn_info(data), :closed)
    {:stop, :normal, data}
  end

  def handle_event(_type, _event, _state, data), do: {:keep_state, data}

  defp read_stored(data) do
    {:ok, stored} = AssemblyStore.read(data.store, data.t2o_assembly)
    stored
  end

  defp track_run_idle(data, nil), do: data
  defp track_run_idle(%{run_state: mode} = data, mode), do: data

  defp track_run_idle(data, mode) do
    data.handler.run_idle_changed(conn_info(data), mode)
    %{data | run_state: mode}
  end

  defp conn_info(data) do
    %{
      triad: data.triad,
      o2t_connection_id: data.o2t_id,
      t2o_connection_id: data.t2o_id,
      o2t_assembly: data.o2t_assembly,
      t2o_assembly: data.t2o_assembly
    }
  end
end
