defmodule Eipex.CIP.Path do
  @moduledoc """
  Padded EPATH codec: logical segments (8/16/32-bit), ANSI extended symbolic
  segments (0x91, padded to even length) and port segments for routing.
  """

  @logical_types [
    class: 0x20,
    instance: 0x24,
    attribute: 0x30,
    member: 0x28,
    connection_point: 0x2C
  ]

  @type segment ::
          {:class | :instance | :attribute | :member | :connection_point, non_neg_integer()}
          | {:symbolic, String.t()}
          | {:port, non_neg_integer(), non_neg_integer()}

  @spec encode([segment()]) :: binary()
  def encode(segments), do: Enum.map_join(segments, &encode_segment/1)

  defp encode_segment({:symbolic, name}) when byte_size(name) in 1..255 do
    pad = if rem(byte_size(name), 2) == 1, do: <<0>>, else: <<>>
    <<0x91, byte_size(name), name::binary, pad::binary>>
  end

  defp encode_segment({:port, port, link}) when port <= 14 and link < 256 do
    <<port, link>>
  end

  defp encode_segment({type, value}) when value < 256 do
    <<Keyword.fetch!(@logical_types, type), value>>
  end

  defp encode_segment({type, value}) when value < 65_536 do
    <<Keyword.fetch!(@logical_types, type) + 1, 0x00, value::16-little>>
  end

  defp encode_segment({:member, value}) do
    <<0x2A, 0x00, value::32-little>>
  end

  @spec words(binary()) :: non_neg_integer()
  def words(path) when is_binary(path), do: div(byte_size(path), 2)

  @spec decode(binary()) :: {:ok, [segment()]} | {:error, :malformed_path}
  def decode(bin), do: decode_segments(bin, [])

  defp decode_segments(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_segments(<<0x91, len, name::binary-size(len), rest::binary>>, acc) do
    rest = if rem(len, 2) == 1, do: strip_pad(rest), else: rest

    case rest do
      {:error, _} = err -> err
      rest -> decode_segments(rest, [{:symbolic, name} | acc])
    end
  end

  defp decode_segments(<<type, value, rest::binary>>, acc)
       when type in [0x20, 0x24, 0x28, 0x2C, 0x30] do
    decode_segments(rest, [{logical_name(type), value} | acc])
  end

  defp decode_segments(<<type, 0x00, value::16-little, rest::binary>>, acc)
       when type in [0x21, 0x25, 0x29, 0x2D, 0x31] do
    decode_segments(rest, [{logical_name(type - 1), value} | acc])
  end

  defp decode_segments(<<0x2A, 0x00, value::32-little, rest::binary>>, acc) do
    decode_segments(rest, [{:member, value} | acc])
  end

  defp decode_segments(<<port, link, rest::binary>>, acc) when port <= 14 do
    decode_segments(rest, [{:port, port, link} | acc])
  end

  defp decode_segments(_, _), do: {:error, :malformed_path}

  defp strip_pad(<<0x00, rest::binary>>), do: rest
  defp strip_pad(<<>>), do: <<>>
  defp strip_pad(_), do: {:error, :malformed_path}

  defp logical_name(code) do
    Enum.find_value(@logical_types, fn {name, c} -> if c == code, do: name end)
  end
end
