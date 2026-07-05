defmodule Eipex.Adapter.Object.MessageRouterObject do
  @moduledoc """
  Message Router object (class 0x02) stub: the routing itself lives in
  `Eipex.Adapter.MessageRouter`; requests addressed to this class (e.g.
  Multiple Service Packet, deferred) answer 0x08.
  """

  @behaviour Eipex.Adapter.Object

  @impl true
  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}
end
