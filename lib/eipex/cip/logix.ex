defmodule Eipex.CIP.Logix do
  @moduledoc """
  Rockwell Logix data-access services (1756-PM020): Read/Write Tag (plain and
  fragmented), Read-Modify-Write, Multiple Service Packet, and the Symbol
  (0x6B) / Template (0x6C) objects used for tag discovery and UDTs.
  Fragmented offsets are byte offsets, not element counts (trap #12).
  """

  alias Eipex.CIP.{MessageRouter, Path, Types}

  @message_router_path [class: 0x02, instance: 0x01]
  @symbol_class 0x6B
  @template_class 0x6C

  # -- Tag services ------------------------------------------------------------

  @spec encode_read_tag(binary() | [Path.segment()], pos_integer()) :: binary()
  def encode_read_tag(path, elements \\ 1) do
    MessageRouter.encode_request(0x4C, path, <<elements::16-little>>)
  end

  @spec encode_read_tag_fragmented(binary() | [Path.segment()], pos_integer(), non_neg_integer()) ::
          binary()
  def encode_read_tag_fragmented(path, elements, byte_offset) do
    MessageRouter.encode_request(0x52, path, <<elements::16-little, byte_offset::32-little>>)
  end

  @spec encode_write_tag(binary() | [Path.segment()], binary(), pos_integer(), binary()) ::
          binary()
  def encode_write_tag(path, type_prefix, elements, data) do
    MessageRouter.encode_request(
      0x4D,
      path,
      <<type_prefix::binary, elements::16-little, data::binary>>
    )
  end

  @spec encode_write_tag_fragmented(
          binary() | [Path.segment()],
          binary(),
          pos_integer(),
          non_neg_integer(),
          binary()
        ) :: binary()
  def encode_write_tag_fragmented(path, type_prefix, elements, byte_offset, data) do
    MessageRouter.encode_request(
      0x53,
      path,
      <<type_prefix::binary, elements::16-little, byte_offset::32-little, data::binary>>
    )
  end

  @valid_mask_sizes [1, 2, 4, 8, 12]

  @spec encode_rmw(binary() | [Path.segment()], binary(), binary()) :: binary()
  def encode_rmw(path, or_mask, and_mask)
      when byte_size(or_mask) == byte_size(and_mask) and
             byte_size(or_mask) in @valid_mask_sizes do
    MessageRouter.encode_request(
      0x4E,
      path,
      <<byte_size(or_mask)::16-little, or_mask::binary, and_mask::binary>>
    )
  end

  # -- Multiple Service Packet -------------------------------------------------

  @spec encode_multiple_service([binary()]) :: binary()
  def encode_multiple_service(requests) do
    count = length(requests)
    first_offset = 2 + count * 2

    {offsets, _} =
      Enum.map_reduce(requests, first_offset, fn req, offset ->
        {<<offset::16-little>>, offset + byte_size(req)}
      end)

    data =
      <<count::16-little, IO.iodata_to_binary(offsets)::binary,
        IO.iodata_to_binary(requests)::binary>>

    MessageRouter.encode_request(0x0A, @message_router_path, data)
  end

  @spec decode_multiple_service_reply(binary()) ::
          {:ok, [binary()]} | {:error, :malformed_msp}
  def decode_multiple_service_reply(
        <<count::16-little, offsets_bin::binary-size(count * 2), _::binary>> = data
      ) do
    offsets = for <<o::16-little <- offsets_bin>>, do: o
    total = byte_size(data)
    bounds = offsets ++ [total]

    replies =
      bounds
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [from, to] ->
        if to > total or from > to, do: :error, else: binary_part(data, from, to - from)
      end)

    if Enum.any?(replies, &(&1 == :error)),
      do: {:error, :malformed_msp},
      else: {:ok, replies}
  end

  def decode_multiple_service_reply(_), do: {:error, :malformed_msp}

  # -- Symbol object (tag list) ------------------------------------------------

  @spec encode_symbol_list(non_neg_integer()) :: binary()
  def encode_symbol_list(start_instance \\ 0) do
    # Instance always in 16-bit format (like pycomm3): iteration walks past 255
    # quickly and a stable path shape simplifies interop.
    path = <<0x20, @symbol_class, 0x25, 0x00, start_instance::16-little>>

    MessageRouter.encode_request(0x55, path, <<2::16-little, 1::16-little, 2::16-little>>)
  end

  @spec decode_symbol_list(binary()) :: {:ok, [map()]} | {:error, :malformed_symbol_list}
  def decode_symbol_list(data), do: decode_symbols(data, [])

  defp decode_symbols(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_symbols(
         <<instance::32-little, name_len::16-little, name::binary-size(name_len),
           raw_type::16-little, rest::binary>>,
         acc
       ) do
    symbol = %{
      instance: instance,
      name: name,
      raw_type: raw_type,
      symbol_type: Types.decode_symbol_type(raw_type)
    }

    decode_symbols(rest, [symbol | acc])
  end

  defp decode_symbols(_, _), do: {:error, :malformed_symbol_list}

  # -- Template object (UDT definitions) ----------------------------------------

  @template_attrs [4, 5, 2, 1]

  @spec encode_template_attributes(non_neg_integer()) :: binary()
  def encode_template_attributes(template_instance) do
    attrs = for a <- @template_attrs, into: <<>>, do: <<a::16-little>>

    MessageRouter.encode_request(
      0x03,
      [class: @template_class, instance: template_instance],
      <<length(@template_attrs)::16-little, attrs::binary>>
    )
  end

  @spec decode_template_attributes(binary()) :: {:ok, map()} | {:error, :malformed_template}
  def decode_template_attributes(<<count::16-little, rest::binary>>) do
    decode_template_attrs(rest, count, %{})
  end

  def decode_template_attributes(_), do: {:error, :malformed_template}

  defp decode_template_attrs(_rest, 0, acc), do: {:ok, acc}

  defp decode_template_attrs(<<id::16-little, 0::16-little, rest::binary>>, n, acc) do
    {key, size} =
      case id do
        1 -> {:handle, 2}
        2 -> {:member_count, 2}
        4 -> {:definition_size, 4}
        5 -> {:structure_size, 4}
      end

    case rest do
      <<value::little-size(size * 8), tail::binary>> ->
        decode_template_attrs(tail, n - 1, Map.put(acc, key, value))

      _ ->
        {:error, :malformed_template}
    end
  end

  defp decode_template_attrs(_, _, _), do: {:error, :malformed_template}

  @spec encode_read_template(non_neg_integer(), non_neg_integer(), pos_integer()) :: binary()
  def encode_read_template(template_instance, byte_offset, bytes) do
    MessageRouter.encode_request(
      0x4C,
      [class: @template_class, instance: template_instance],
      <<byte_offset::32-little, bytes::16-little>>
    )
  end

  @spec decode_template_definition(binary(), pos_integer()) ::
          {:ok, %{name: String.t(), members: [map()]}} | {:error, :malformed_template}
  def decode_template_definition(binary, member_count) do
    meta_size = member_count * 8

    with <<meta::binary-size(meta_size), names_bin::binary>> <- binary,
         [template_name | member_names] <- split_names(names_bin, member_count + 1) do
      metas =
        for <<info::16-little, raw_type::16-little, offset::32-little <- meta>> do
          %{
            info: info,
            raw_type: raw_type,
            symbol_type: Types.decode_symbol_type(raw_type),
            offset: offset
          }
        end

      members =
        metas
        |> Enum.zip(member_names)
        |> Enum.map(fn {meta_map, name} -> Map.put(meta_map, :name, name) end)

      name = template_name |> String.split(";") |> hd()
      {:ok, %{name: name, members: members}}
    else
      _ -> {:error, :malformed_template}
    end
  end

  defp split_names(bin, count) do
    names = bin |> :binary.split(<<0>>, [:global, :trim_all]) |> Enum.take(count)
    if length(names) == count, do: names, else: :error
  end
end
