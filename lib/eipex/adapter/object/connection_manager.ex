defmodule Eipex.Adapter.Object.ConnectionManager do
  @moduledoc """
  Connection Manager object (class 0x06).

  UCMM subset: Unconnected Send is unwrapped and dispatched locally
  (single-hop routes are accepted — this device is the target).

  Forward Open/Forward Close are implemented for transport class 3
  (explicit messaging over a connection) and class 1 (cyclic implicit I/O,
  backed by `Eipex.Adapter.IoConnection`); any other transport class
  answers 0x0103 (transport/trigger not supported).

  Deviation from spec §5: class 3 connections have no per-connection
  inactivity watchdog in this version. A real target closes a connection
  once `o2t_rpi * timeout_multiplier` elapses without traffic; here a
  connection is only released when its owning TCP session ends (clean
  unregister, socket close, or crash) — see `ConnectionTable`'s
  monitor-based cleanup. Callers that need timely reclamation must close
  the encapsulation session or issue Forward Close explicitly. Class 1
  connections are not affected: `IoConnection` runs its own watchdog.
  """

  @behaviour Eipex.Adapter.Object

  alias Eipex.CIP.ConnectionManager, as: CM

  @unconnected_send 0x52
  @forward_close 0x4E
  @forward_open 0x54
  @large_forward_open 0x5B

  @impl true
  def handle_service(@unconnected_send, 1, [], data, ctx) do
    case CM.decode_unconnected_send(data) do
      {:ok, %{embedded: embedded}} ->
        {:raw, Eipex.Adapter.MessageRouter.dispatch(ctx.config, embedded)}

      {:error, _} ->
        {:error, 0x13, []}
    end
  end

  def handle_service(service, 1, [], data, ctx)
      when service in [@forward_open, @large_forward_open] do
    case CM.decode_forward_open(service, data) do
      {:ok, fo} -> open_connection(fo, ctx)
      {:error, _} -> {:error, 0x13, []}
    end
  end

  def handle_service(@forward_close, 1, [], data, ctx) do
    case CM.decode_forward_close(data) do
      {:ok, fc} ->
        triad = {fc.connection_serial, fc.originator_vendor_id, fc.originator_serial}

        case Eipex.Adapter.ConnectionTable.unregister(ctx.connections, triad) do
          {:ok, record} ->
            send(ctx.session, {:connection_closed, record.o2t_id})
            if record.kind == :io, do: send(record.pid, :close)

            {:reply,
             CM.encode_forward_close_reply(%{
               connection_serial: fc.connection_serial,
               originator_vendor_id: fc.originator_vendor_id,
               originator_serial: fc.originator_serial
             })}

          {:error, :not_found} ->
            {:error, 0x01, [0x0107]}
        end

      {:error, _} ->
        {:error, 0x13, []}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp open_connection(fo, ctx) do
    case fo.transport do
      # existing explicit flow
      %{class: 3} -> open_explicit(fo, ctx)
      %{class: 1} -> open_io(fo, ctx)
      _ -> {:error, 0x01, [0x0103]}
    end
  end

  defp open_explicit(fo, ctx) do
    with :ok <- validate_path(fo) do
      triad = {fo.connection_serial, fo.originator_vendor_id, fo.originator_serial}
      info = %{t2o_connection_id: fo.t2o_connection_id}

      case Eipex.Adapter.ConnectionTable.register(ctx.connections, triad, info, ctx.session) do
        {:ok, o2t_id} ->
          {:reply,
           CM.encode_forward_open_reply(%CM.ForwardOpenReply{
             o2t_connection_id: o2t_id,
             t2o_connection_id: fo.t2o_connection_id,
             connection_serial: fo.connection_serial,
             originator_vendor_id: fo.originator_vendor_id,
             originator_serial: fo.originator_serial,
             o2t_api: fo.o2t_rpi,
             t2o_api: fo.t2o_rpi,
             application_reply: <<>>
           })}

        {:error, :duplicate} ->
          {:error, 0x01, [0x0100]}

        {:error, :capacity} ->
          {:error, 0x01, [0x0113]}
      end
    end
  end

  defp validate_path(fo) do
    case Eipex.CIP.Path.decode(fo.connection_path) do
      {:ok, segments} ->
        segments
        |> Enum.drop_while(&match?({:port, _, _}, &1))
        |> case do
          [class: 0x02, instance: 0x01] -> :ok
          _ -> {:error, 0x01, [0x0315]}
        end

      {:error, _} ->
        {:error, 0x01, [0x0315]}
    end
  end

  # -- Class 1 (cyclic implicit I/O) -------------------------------------------

  defp open_io(fo, ctx) do
    with :ok <- validate_io_types(fo),
         :ok <- validate_rpis(fo),
         {:ok, cfg, o2t_asm, t2o_asm} <- validate_io_path(fo),
         {:ok, out_size} <- assembly_kind(ctx, o2t_asm, :output, 0x012A),
         {:ok, in_size} <- assembly_kind(ctx, t2o_asm, :input, 0x012B),
         :ok <- validate_config_instance(ctx, cfg),
         :ok <-
           validate_io_size(fo.o2t_params.size, out_size, ctx.config.io.o2t_run_idle, 0x0127),
         :ok <- validate_io_size(fo.t2o_params.size, in_size, ctx.config.io.t2o_run_idle, 0x0128) do
      start_io_connection(fo, ctx, o2t_asm, t2o_asm)
    end
  end

  defp validate_io_types(fo) do
    cond do
      fo.o2t_params.type != :point_to_point -> {:error, 0x01, [0x0123]}
      fo.t2o_params.type != :point_to_point -> {:error, 0x01, [0x0124]}
      true -> :ok
    end
  end

  defp validate_rpis(fo) do
    if fo.o2t_rpi in 1_000..10_000_000 and fo.t2o_rpi in 1_000..10_000_000 do
      :ok
    else
      {:error, 0x01, [0x0111]}
    end
  end

  defp validate_io_path(fo) do
    case Eipex.CIP.Path.decode(fo.connection_path) do
      {:ok, segments} ->
        segments
        |> Enum.drop_while(&match?({:port, _, _}, &1))
        |> case do
          [{:class, 0x04}, {:instance, cfg}, {:connection_point, o2t}, {:connection_point, t2o}] ->
            {:ok, cfg, o2t, t2o}

          [{:class, 0x04}, {:connection_point, o2t}, {:connection_point, t2o}] ->
            {:ok, nil, o2t, t2o}

          _ ->
            {:error, 0x01, [0x0315]}
        end

      {:error, _} ->
        {:error, 0x01, [0x0315]}
    end
  end

  defp assembly_kind(ctx, instance, expected_kind, ext) do
    case Eipex.Adapter.AssemblyStore.info(ctx.store, instance) do
      {:ok, %{kind: ^expected_kind, size: size}} -> {:ok, size}
      _ -> {:error, 0x01, [ext]}
    end
  end

  defp validate_config_instance(_ctx, nil), do: :ok

  defp validate_config_instance(ctx, cfg) do
    case Eipex.Adapter.AssemblyStore.info(ctx.store, cfg) do
      {:ok, %{kind: :config}} -> :ok
      _ -> {:error, 0x01, [0x0129]}
    end
  end

  defp validate_io_size(param_size, data_size, run_idle?, ext) do
    correct_size = Eipex.IO.wire_size(data_size, run_idle?)

    if param_size == correct_size do
      :ok
    else
      {:error, 0x01, [ext, correct_size]}
    end
  end

  defp start_io_connection(fo, ctx, o2t_asm, t2o_asm) do
    triad = {fo.connection_serial, fo.originator_vendor_id, fo.originator_serial}
    peer = resolve_peer(ctx)

    args = %{
      table: ctx.connections,
      store: ctx.store,
      handler: ctx.handler,
      udp: ctx.config.io.udp,
      triad: triad,
      t2o_id: fo.t2o_connection_id,
      o2t_assembly: o2t_asm,
      t2o_assembly: t2o_asm,
      o2t_size: fo.o2t_params.size - overhead(ctx.config.io.o2t_run_idle),
      o2t_run_idle: ctx.config.io.o2t_run_idle,
      t2o_run_idle: ctx.config.io.t2o_run_idle,
      t2o_rpi_ms: Eipex.IO.rpi_ms(fo.t2o_rpi),
      watchdog_ms: Eipex.IO.rpi_ms(fo.o2t_rpi) * CM.timeout_factor(fo.timeout_multiplier)
    }

    {:ok, statem} =
      DynamicSupervisor.start_child(ctx.config.io.sup, {Eipex.Adapter.IoConnection, args})

    info = %{t2o_connection_id: fo.t2o_connection_id, kind: :io, pid: statem}

    # The monitored OWNER of a class 1 connection is the statem itself, NOT the
    # TCP session (class 1 connections survive session close per spec; they die
    # by watchdog or Forward Close). Passing the statem as the session argument
    # means both monitor paths point at the statem.
    case Eipex.Adapter.ConnectionTable.register(ctx.connections, triad, info, statem) do
      {:ok, o2t_id} ->
        Eipex.Adapter.IoConnection.activate(statem, o2t_id, peer)
        {:ok, udp_port} = Eipex.Adapter.UDP.port(ctx.config.io.udp)

        {:reply,
         CM.encode_forward_open_reply(%CM.ForwardOpenReply{
           o2t_connection_id: o2t_id,
           t2o_connection_id: fo.t2o_connection_id,
           connection_serial: fo.connection_serial,
           originator_vendor_id: fo.originator_vendor_id,
           originator_serial: fo.originator_serial,
           o2t_api: fo.o2t_rpi,
           t2o_api: fo.t2o_rpi,
           application_reply: <<>>
         }), [{:sockaddr_o2t, %{ip: {0, 0, 0, 0}, port: udp_port}}]}

      {:error, :duplicate} ->
        :gen_statem.stop(statem)
        {:error, 0x01, [0x0100]}

      {:error, :capacity} ->
        :gen_statem.stop(statem)
        {:error, 0x01, [0x0113]}
    end
  end

  defp overhead(run_idle?), do: 2 + if(run_idle?, do: 4, else: 0)

  defp resolve_peer(ctx) do
    case for {:sockaddr_t2o, sa} <- Map.get(ctx, :cpf_items, []), do: sa do
      [%{ip: {0, 0, 0, 0}, port: port} | _] -> {Map.get(ctx, :peer_ip, {127, 0, 0, 1}), port}
      [%{ip: ip, port: port} | _] -> {ip, port}
      [] -> {Map.get(ctx, :peer_ip, {127, 0, 0, 1}), 2222}
    end
  end
end
