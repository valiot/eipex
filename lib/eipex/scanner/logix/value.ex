defmodule Eipex.Scanner.Logix.Value do
  @moduledoc """
  Decodes Logix read replies into Elixir terms and encodes terms for writes,
  using a UDT template registry (handle => template).

  Decode (`decode_reply/2`) covers atomic values, arrays, member-map
  structures and Logix STRING structs. Encode (`encode/3`) is narrower: only
  atomic *scalar* values (and `:bool`) are supported for writes; struct
  values are rejected with `:struct_write_unsupported`, and multi-element
  array writes are not implemented.

  A template is `%{name, members, structure_size}` as produced by
  `Eipex.CIP.Logix.decode_template_definition/2` (registry adds
  `structure_size` from the Template object's attributes). Each member is
  `%{name, raw_type, symbol_type, offset, info}`.

  Nested structures are decoded up to two levels deep (the top-level struct
  plus one level of struct-typed members); a third level returns
  `{:error, :nesting_too_deep}` instead of recursing further.
  """

  import Bitwise

  alias Eipex.CIP.Types

  @max_nesting 2

  @spec decode_reply(binary(), map()) :: {:ok, term()} | {:error, term()}
  def decode_reply(<<0xA0, 0x02, handle::16-little, body::binary>>, templates) do
    case Map.fetch(templates, handle) do
      {:ok, template} -> decode_struct(template, body, templates)
      :error -> {:ok, {:struct, handle, body}}
    end
  end

  def decode_reply(reply_data, _templates) do
    case Types.decode_typed(reply_data) do
      {:ok, {:short_string, s}} -> {:ok, s}
      {:ok, {_type, value}} -> {:ok, value}
      {:error, _} = error -> error
    end
  end

  @doc """
  Decodes a struct body against `template`. A Logix-STRING-shaped template
  decodes to an Elixir string; otherwise each member is decoded at its
  `offset` into a `%{member_name => value}` map.
  """
  @spec decode_struct(map(), binary(), map()) :: {:ok, map() | String.t()} | {:error, term()}
  def decode_struct(template, body, templates), do: decode_struct(template, body, templates, 1)

  defp decode_struct(template, body, templates, level) do
    if string?(template) do
      decode_string(template, body)
    else
      decode_members(template, body, templates, level)
    end
  end

  @doc "True when `template` is the two-member Logix STRING layout (LEN + DATA)."
  @spec string?(map()) :: boolean()
  def string?(%{members: members}) do
    case members do
      [%{name: len_name} = len, %{name: data_name} = data] ->
        String.upcase(len_name) == "LEN" and String.upcase(data_name) == "DATA" and
          len.symbol_type.atomic_type in [:dint, :int] and
          data.symbol_type.atomic_type == :sint

      _ ->
        false
    end
  end

  def string?(_), do: false

  @spec encode(term(), atom() | {:struct, term()}, map()) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def encode(_value, {:struct, _instance}, _templates), do: {:error, :struct_write_unsupported}

  def encode(value, :bool, _templates) do
    byte = if value, do: 0xFF, else: 0x00
    {:ok, {<<Types.type_code(:bool)::16-little>>, <<byte>>}}
  end

  def encode(value, type, _templates) when is_atom(type) do
    case Types.encode(type, value) do
      {:ok, bytes} -> {:ok, {<<Types.type_code(type)::16-little>>, bytes}}
      {:error, _} = error -> error
    end
  end

  def encode(_value, _type, _templates), do: {:error, :unsupported_type}

  # -- Logix STRING decode ------------------------------------------------------

  defp decode_string(template, body) do
    members_by_name = Map.new(template.members, fn m -> {String.upcase(m.name), m} end)
    len_member = members_by_name["LEN"]
    data_member = members_by_name["DATA"]
    len_size = element_size(len_member.symbol_type.atomic_type)

    with {:ok, len_bytes} <- slice(body, len_member.offset, len_size),
         {:ok, len} <- Types.decode(len_member.symbol_type.atomic_type, len_bytes),
         {:ok, data} <- slice(body, data_member.offset, len) do
      {:ok, data}
    end
  end

  # -- Member-map decode ---------------------------------------------------------

  defp decode_members(template, body, templates, level) do
    %{members: members, structure_size: structure_size} = template
    sorted = Enum.sort_by(members, & &1.offset)
    next_offsets = sorted |> Enum.map(& &1.offset) |> Enum.drop(1) |> Kernel.++([structure_size])

    sorted
    |> Enum.zip(next_offsets)
    |> Enum.reduce_while({:ok, %{}}, fn {member, next_offset}, {:ok, acc} ->
      case decode_member(member, next_offset, body, templates, level) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, member.name, value)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  # 1756-PM020 §7 template member layout (INFO/UINT + Data Type/UINT +
  # Offset/UDINT): INFO holds the bit position for a BOOL member. Confirmed
  # independently in pycomm3 (logix_driver.py: `type_info` is read before the
  # type code, then `member["bit"] = type_info` for BOOL). `bool_position`
  # (from the Symbol object's type word) is unrelated to Template members.
  defp decode_member(
         %{symbol_type: %{atomic_type: :bool}, info: pos} = member,
         _next,
         body,
         _templates,
         _level
       ) do
    case slice(body, member.offset, 1) do
      {:ok, <<byte>>} -> {:ok, (byte &&& 1 <<< pos) != 0}
      error -> error
    end
  end

  defp decode_member(
         %{symbol_type: %{structure?: true, template_instance: handle}} = member,
         next_offset,
         body,
         templates,
         level
       ) do
    cond do
      level >= @max_nesting ->
        {:error, :nesting_too_deep}

      not Map.has_key?(templates, handle) ->
        {:error, {:unknown_template, handle}}

      true ->
        with {:ok, slice_bin} <- slice(body, member.offset, next_offset - member.offset) do
          decode_struct(Map.fetch!(templates, handle), slice_bin, templates, level + 1)
        end
    end
  end

  defp decode_member(
         %{symbol_type: %{atomic_type: atomic_type}, info: count} = member,
         _next,
         body,
         _templates,
         _level
       )
       when is_atom(atomic_type) and not is_nil(atomic_type) and is_integer(count) and count >= 2 do
    case element_size(atomic_type) do
      nil ->
        {:error, {:unknown_type, atomic_type}}

      size ->
        with {:ok, chunk} <- slice(body, member.offset, size * count) do
          decode_array_elements(atomic_type, chunk, size)
        end
    end
  end

  defp decode_member(
         %{symbol_type: %{atomic_type: atomic_type}} = member,
         _next,
         body,
         _templates,
         _level
       )
       when is_atom(atomic_type) and not is_nil(atomic_type) do
    case element_size(atomic_type) do
      nil ->
        {:error, {:unknown_type, atomic_type}}

      size ->
        with {:ok, chunk} <- slice(body, member.offset, size) do
          Types.decode(atomic_type, chunk)
        end
    end
  end

  defp decode_member(_member, _next, _body, _templates, _level), do: {:error, :bad_member}

  defp decode_array_elements(_atomic_type, <<>>, _element_size), do: {:ok, []}

  defp decode_array_elements(atomic_type, chunk, element_size) do
    <<element::binary-size(element_size), rest::binary>> = chunk

    with {:ok, value} <- Types.decode(atomic_type, element),
         {:ok, values} <- decode_array_elements(atomic_type, rest, element_size) do
      {:ok, [value | values]}
    end
  end

  defp slice(body, offset, size) when offset >= 0 and size >= 0 do
    if offset + size <= byte_size(body) do
      {:ok, binary_part(body, offset, size)}
    else
      {:error, :short_body}
    end
  end

  defp slice(_body, _offset, _size), do: {:error, :short_body}

  defp element_size(name) when name in [:bool, :sint, :usint, :byte], do: 1
  defp element_size(name) when name in [:int, :uint, :word], do: 2
  defp element_size(name) when name in [:dint, :udint, :dword, :real], do: 4
  defp element_size(name) when name in [:lint, :ulint, :lword, :lreal], do: 8
  defp element_size(_name), do: nil
end
