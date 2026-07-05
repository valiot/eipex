defmodule Eipex.Adapter.Object.Identity do
  @moduledoc "Identity object (class 0x01): attributes 1-7 and Reset."

  @behaviour Eipex.Adapter.Object

  @get_attributes_all 0x01
  @reset 0x05
  @get_attribute_single 0x0E

  @impl true
  def handle_service(@get_attributes_all, 1, [], <<>>, ctx) do
    {:reply, Enum.map_join(1..7, &attribute(&1, ctx.config.identity))}
  end

  def handle_service(@get_attribute_single, 1, [{:attribute, n}], <<>>, ctx) do
    case attribute(n, ctx.config.identity) do
      nil -> {:error, 0x14, []}
      data -> {:reply, data}
    end
  end

  def handle_service(@reset, 1, [], data, ctx) do
    type =
      case data do
        <<>> -> 0
        <<t, _::binary>> -> t
      end

    case ctx.handler.reset(type) do
      :ok -> {:reply, <<>>}
      {:error, status} -> {:error, status, []}
    end
  end

  def handle_service(_service, 1, _path, _data, _ctx), do: {:error, 0x08, []}
  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x05, []}

  defp attribute(1, id), do: <<id.vendor_id::16-little>>
  defp attribute(2, id), do: <<id.device_type::16-little>>
  defp attribute(3, id), do: <<id.product_code::16-little>>
  defp attribute(4, %{revision: {major, minor}}), do: <<major, minor>>
  defp attribute(5, id), do: <<id.status::16-little>>
  defp attribute(6, id), do: <<id.serial_number::32-little>>
  defp attribute(7, id), do: <<byte_size(id.product_name), id.product_name::binary>>
  defp attribute(_, _), do: nil
end
