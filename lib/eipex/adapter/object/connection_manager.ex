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

  def handle_service(service, 1, _path, _data, _ctx)
      when service in [@forward_open, @large_forward_open, @forward_close] do
    {:error, 0x08, []}
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}
end
