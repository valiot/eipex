defmodule Eipex.CPF do
  @moduledoc """
  Common Packet Format: item count + (type, length, data) items.
  Carried inside SendRRData/SendUnitData and class 1 UDP datagrams.
  """

  alias Eipex.Identity

  @type item ::
          :null_address
          | {:connected_address, non_neg_integer()}
          | {:sequenced_address, non_neg_integer(), non_neg_integer()}
          | {:unconnected_data, binary()}
          | {:connected_data, binary()}
          | {:sockaddr_o2t, %{ip: :inet.ip4_address(), port: non_neg_integer()}}
          | {:sockaddr_t2o, %{ip: :inet.ip4_address(), port: non_neg_integer()}}
          | {:identity, Identity.t()}
          | {:unknown, non_neg_integer(), binary()}

  @spec encode([item()]) :: binary()
  def encode(items) do
    body = Enum.map_join(items, &encode_item/1)
    <<length(items)::16-little, body::binary>>
  end

  defp encode_item(:null_address), do: <<0x0000::16-little, 0::16-little>>

  defp encode_item({:connected_address, id}),
    do: <<0x00A1::16-little, 4::16-little, id::32-little>>

  defp encode_item({:sequenced_address, id, seq}),
    do: <<0x8002::16-little, 8::16-little, id::32-little, seq::32-little>>

  defp encode_item({:unconnected_data, data}),
    do: <<0x00B2::16-little, byte_size(data)::16-little, data::binary>>

  defp encode_item({:connected_data, data}),
    do: <<0x00B1::16-little, byte_size(data)::16-little, data::binary>>

  defp encode_item({:sockaddr_o2t, sa}), do: encode_sockaddr(0x8000, sa)
  defp encode_item({:sockaddr_t2o, sa}), do: encode_sockaddr(0x8001, sa)

  defp encode_item({:identity, %Identity{} = id}) do
    body = Identity.encode_item(id)
    <<0x000C::16-little, byte_size(body)::16-little, body::binary>>
  end

  defp encode_sockaddr(type, %{ip: {a, b, c, d}, port: port}) do
    <<type::16-little, 16::16-little, 2::16-big, port::16-big, a, b, c, d, 0::64>>
  end

  @spec decode(binary()) :: {:ok, [item()]} | {:error, :malformed_cpf}
  def decode(<<count::16-little, body::binary>>), do: decode_items(body, count, [])
  def decode(_), do: {:error, :malformed_cpf}

  defp decode_items(<<>>, 0, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_items(_rest, 0, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_items(
         <<type::16-little, len::16-little, data::binary-size(len), rest::binary>>,
         n,
         acc
       ) do
    case decode_item(type, data) do
      {:ok, item} -> decode_items(rest, n - 1, [item | acc])
      :error -> {:error, :malformed_cpf}
    end
  end

  defp decode_items(_, _, _), do: {:error, :malformed_cpf}

  defp decode_item(0x0000, <<>>), do: {:ok, :null_address}
  defp decode_item(0x00A1, <<id::32-little>>), do: {:ok, {:connected_address, id}}

  defp decode_item(0x8002, <<id::32-little, seq::32-little>>),
    do: {:ok, {:sequenced_address, id, seq}}

  defp decode_item(0x00B2, data), do: {:ok, {:unconnected_data, data}}
  defp decode_item(0x00B1, data), do: {:ok, {:connected_data, data}}

  defp decode_item(type, <<_family::16-big, port::16-big, a, b, c, d, _::64>>)
       when type in [0x8000, 0x8001] do
    tag = if type == 0x8000, do: :sockaddr_o2t, else: :sockaddr_t2o
    {:ok, {tag, %{ip: {a, b, c, d}, port: port}}}
  end

  defp decode_item(0x000C, data) do
    case Identity.decode_item(data) do
      {:ok, id} -> {:ok, {:identity, id}}
      {:error, _} -> :error
    end
  end

  defp decode_item(type, data), do: {:ok, {:unknown, type, data}}
end
