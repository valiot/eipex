defmodule Eipex.Scanner.Logix do
  @moduledoc """
  Logix tag discovery over the Symbol (0x6B) and Template (0x6C) objects
  (1756-PM020).

  `tag_list/2` walks the Symbol Object's Get_Instance_Attribute_List service
  (0x55), following its `:partial_transfer` continuations, then fetches each
  distinct structured tag's UDT definition from the Template Object exactly
  once (attributes via Get_Attribute_List, then a fragmented Read Template
  loop).
  """

  alias Eipex.CIP.Logix, as: LogixCodec
  alias Eipex.Scanner

  @template_class 0x6C
  @template_attrs [4, 5, 2, 1]

  defmodule Tag do
    @moduledoc """
    One entry from the Symbol Object catalog.

    `type` is an atomic type atom (`:dint`, `:real`, ...), `{:struct,
    handle}` for a structured tag (keyed into the sibling `templates`
    registry returned by `tag_list/2`), or `{:array, base, dims}` when the
    symbol reports one or more array dimensions.
    """
    defstruct [:name, :instance, :raw_type, :type, :dims, :system?]

    @type t :: %__MODULE__{
            name: String.t(),
            instance: non_neg_integer(),
            raw_type: non_neg_integer(),
            type: atom() | {:struct, non_neg_integer()} | {:array, term(), 1..3},
            dims: 0..3,
            system?: boolean()
          }
  end

  @doc """
  Discovers the target's tag catalog.

  Walks the Symbol Object from instance 0, following `:partial_transfer`
  continuations, classifies each symbol's type, and fetches (once per
  distinct template) the UDT definition backing every structured tag that
  will be returned. System tags — Logix's hidden bit, a `__`-prefixed name,
  or a name containing `:` — are excluded from `:tags` unless
  `opts[:include_system]` is true (they are still flagged via `system?`).

  Returns `{:ok, %{tags: [%Tag{}], templates: %{handle => template}}}`,
  where `template` is the map produced by
  `Eipex.CIP.Logix.decode_template_definition/2` plus a merged
  `:structure_size`. A CIP error on any symbol-list or template fetch
  surfaces as `{:error, {:cip, status_name, extended}}`; a transport error
  surfaces as-is.
  """
  @spec tag_list(GenServer.server(), keyword()) ::
          {:ok, %{tags: [Tag.t()], templates: map()}} | {:error, term()}
  def tag_list(server, opts \\ []) do
    include_system? = Keyword.get(opts, :include_system, false)

    with {:ok, symbols} <- fetch_symbols(server, 0, []) do
      classified = Enum.map(symbols, &classify/1)
      kept = if include_system?, do: classified, else: Enum.reject(classified, & &1.system?)

      template_instances =
        kept |> Enum.map(& &1.template_instance) |> Enum.reject(&is_nil/1) |> Enum.uniq()

      with {:ok, registry, handles} <- fetch_templates(server, template_instances) do
        {:ok, %{tags: Enum.map(kept, &to_tag(&1, handles)), templates: registry}}
      end
    end
  end

  # -- Symbol Object iteration (service 0x55) ----------------------------------

  defp fetch_symbols(server, start_instance, acc) do
    path = <<0x20, 0x6B, 0x25, 0x00, start_instance::16-little>>
    data = <<2::16-little, 1::16-little, 2::16-little>>

    case Scanner.generic_message(server, service: 0x55, path: path, data: data) do
      {:ok, %{status_name: :success, data: reply}} ->
        with {:ok, symbols} <- LogixCodec.decode_symbol_list(reply), do: {:ok, acc ++ symbols}

      {:ok, %{status_name: :partial_transfer, data: reply}} ->
        with {:ok, symbols} <- LogixCodec.decode_symbol_list(reply) do
          case symbols do
            [] ->
              {:error, :malformed_symbol_list}

            _ ->
              next_instance = List.last(symbols).instance + 1
              fetch_symbols(server, next_instance, acc ++ symbols)
          end
        end

      {:ok, %{status_name: name, extended: extended}} ->
        {:error, {:cip, name, extended}}

      {:error, _} = error ->
        error
    end
  end

  defp classify(%{instance: instance, name: name, raw_type: raw_type, symbol_type: symbol_type}) do
    %{
      name: name,
      instance: instance,
      raw_type: raw_type,
      dims: symbol_type.dims,
      atomic_type: symbol_type.atomic_type,
      template_instance: symbol_type.template_instance,
      system?: symbol_type.system? or hidden_name?(name)
    }
  end

  defp hidden_name?(name), do: String.starts_with?(name, "__") or String.contains?(name, ":")

  defp to_tag(classified, handles) do
    %Tag{
      name: classified.name,
      instance: classified.instance,
      raw_type: classified.raw_type,
      type: resolve_type(classified, handles),
      dims: classified.dims,
      system?: classified.system?
    }
  end

  defp resolve_type(%{template_instance: nil, atomic_type: base, dims: 0}, _handles), do: base

  defp resolve_type(%{template_instance: nil, atomic_type: base, dims: dims}, _handles),
    do: {:array, base, dims}

  defp resolve_type(%{template_instance: ti, dims: 0}, handles),
    do: {:struct, Map.fetch!(handles, ti)}

  defp resolve_type(%{template_instance: ti, dims: dims}, handles),
    do: {:array, {:struct, Map.fetch!(handles, ti)}, dims}

  # -- Template Object fetch (class 0x6C) --------------------------------------

  defp fetch_templates(server, template_instances) do
    Enum.reduce_while(template_instances, {:ok, %{}, %{}}, fn ti, {:ok, registry, handles} ->
      case fetch_template(server, ti) do
        {:ok, handle, template} ->
          {:cont, {:ok, Map.put(registry, handle, template), Map.put(handles, ti, handle)}}

        {:error, _} = error ->
          {:halt, error}
      end
    end)
  end

  defp fetch_template(server, template_instance) do
    with {:ok, attrs} <- fetch_template_attributes(server, template_instance),
         {:ok, definition} <-
           fetch_template_definition(server, template_instance, attrs.definition_size),
         {:ok, template} <- LogixCodec.decode_template_definition(definition, attrs.member_count) do
      {:ok, attrs.handle, Map.put(template, :structure_size, attrs.structure_size)}
    end
  end

  defp fetch_template_attributes(server, template_instance) do
    ids = for id <- @template_attrs, into: <<>>, do: <<id::16-little>>
    data = <<length(@template_attrs)::16-little, ids::binary>>

    case Scanner.generic_message(server,
           service: 0x03,
           path: [class: @template_class, instance: template_instance],
           data: data
         ) do
      {:ok, %{status_name: :success, data: reply}} ->
        LogixCodec.decode_template_attributes(reply)

      {:ok, %{status_name: name, extended: extended}} ->
        {:error, {:cip, name, extended}}

      {:error, _} = error ->
        error
    end
  end

  defp fetch_template_definition(server, template_instance, definition_size) do
    read_definition(server, template_instance, 0, definition_size * 4 - 23, <<>>)
  end

  defp read_definition(server, template_instance, offset, total_bytes, acc) do
    bytes = total_bytes - offset

    case Scanner.generic_message(server,
           service: 0x4C,
           path: [class: @template_class, instance: template_instance],
           data: <<offset::32-little, bytes::16-little>>
         ) do
      {:ok, %{status_name: :success, data: chunk}} ->
        {:ok, acc <> chunk}

      {:ok, %{status_name: :partial_transfer, data: chunk}} ->
        if byte_size(chunk) > 0 do
          read_definition(
            server,
            template_instance,
            offset + byte_size(chunk),
            total_bytes,
            acc <> chunk
          )
        else
          {:error, :malformed_template}
        end

      {:ok, %{status_name: name, extended: extended}} ->
        {:error, {:cip, name, extended}}

      {:error, _} = error ->
        error
    end
  end
end
