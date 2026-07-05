defmodule Eipex.Adapter.Object.ConnectionManager do
  @moduledoc """
  Connection Manager object (class 0x06), UCMM subset: Unconnected Send is
  unwrapped and dispatched locally (single-hop routes are accepted — this
  device is the target). Forward Open/Close arrive in Phase 4.
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
          {:ok, _record} ->
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
    with :ok <- validate_transport(fo),
         :ok <- validate_path(fo) do
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

  defp validate_transport(%{transport: %{class: 3}}), do: :ok
  defp validate_transport(_fo), do: {:error, 0x01, [0x0103]}

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
end
