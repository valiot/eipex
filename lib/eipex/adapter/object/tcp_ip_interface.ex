defmodule Eipex.Adapter.Object.TcpIpInterface do
  @moduledoc """
  TCP/IP Interface object (class 0xF5). Attribute values come from the
  adapter's `network` options. IPs encode as UDINT little-endian of the
  network-order integer (`{a,b,c,d}` -> `<<d, c, b, a>>`).
  """

  @behaviour Eipex.Adapter.Object

  @get_attribute_single 0x0E

  @impl true
  def handle_service(@get_attribute_single, 1, [{:attribute, n}], <<>>, ctx) do
    case attribute(n, ctx.config) do
      nil -> {:error, 0x14, []}
      data -> {:reply, data}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp attribute(1, _config), do: <<1::32-little>>
  defp attribute(2, _config), do: <<0::32-little>>
  defp attribute(3, _config), do: <<0::32-little>>
  defp attribute(4, _config), do: <<2::16-little, 0x20, 0xF6, 0x24, 0x01>>

  defp attribute(5, config) do
    net = config.network

    encode_ip(Map.get(net, :ip, {0, 0, 0, 0})) <>
      encode_ip(Map.get(net, :netmask, {0, 0, 0, 0})) <>
      encode_ip(Map.get(net, :gateway, {0, 0, 0, 0})) <>
      <<0::32, 0::32>> <>
      encode_string(Map.get(net, :domain, ""))
  end

  defp attribute(6, config), do: encode_string(Map.get(config.network, :hostname, ""))
  defp attribute(8, _config), do: <<1>>
  defp attribute(13, config), do: <<div(config.inactivity_timeout, 1000)::16-little>>
  defp attribute(_, _config), do: nil

  defp encode_ip({a, b, c, d}), do: <<d, c, b, a>>
  defp encode_string(s), do: <<byte_size(s)::16-little, s::binary>>
end
