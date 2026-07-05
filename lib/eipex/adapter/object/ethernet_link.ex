defmodule Eipex.Adapter.Object.EthernetLink do
  @moduledoc "Ethernet Link object (class 0xF6): speed, flags and MAC."

  @behaviour Eipex.Adapter.Object

  @get_attribute_single 0x0E

  @impl true
  def handle_service(@get_attribute_single, 1, [{:attribute, n}], <<>>, ctx) do
    case attribute(n, ctx.config.network) do
      nil -> {:error, 0x14, []}
      data -> {:reply, data}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp attribute(1, net), do: <<Map.get(net, :speed, 100)::32-little>>
  defp attribute(2, _net), do: <<3::32-little>>
  defp attribute(3, net), do: Map.get(net, :mac, <<0, 0, 0, 0, 0, 0>>)
  defp attribute(_, _net), do: nil
end
