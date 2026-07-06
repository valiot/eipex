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
  alias Eipex.CIP.{MessageRouter, Types}
  alias Eipex.Scanner
  alias Eipex.Scanner.Logix.Value

  @template_class 0x6C
  @template_attrs [4, 5, 2, 1]

  @default_connection_size 500
  @default_tag_estimate 8
  @multiple_service_path [class: 0x02, instance: 1]

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

  # -- Tag read (services 0x4C, 0x52, 0x0A) ------------------------------------

  @doc """
  Reads one tag or a list of tags.

  A single `name` (a plain symbolic tag name, e.g. `"Rate"` or
  `"Program:Main.Count"`) is read with a single Read Tag request
  (`opts[:elements]`, default 1); a reply too big for one message
  (`:partial_transfer`) switches to a Read Tag Fragmented loop that
  reassembles the full value (stripping the repeated type header off every
  continuation) before decoding. Returns `{:ok, %Eipex.Tag{}}`.

  A list of names is read in batches packed into Multiple Service Packets,
  each batch kept under `opts[:connection_size]` (default 500 bytes) by an
  estimate of each tag's encoded reply size; a tag whose estimate alone
  exceeds the threshold is read individually instead (fragmented if needed,
  never inside an MSP). A batched sub-reply that turns out too big
  (`:partial_transfer`) falls back to an individual fragmented read for that
  one tag. Returns `{:ok, [%Eipex.Tag{}]}` in the same order as the input
  list.

  `opts[:tags]` is the `%{tags: [...], templates: %{...}}` catalog from
  `tag_list/2`; its `:templates` registry lets structured tags decode into
  member maps (and lets bulk reads estimate structure sizes accurately).
  Without it, atomics still decode and structures pass through raw as
  `{:struct, handle, bytes}`.

  This call only returns `{:error, reason}` for a transport/session failure;
  CIP-level and per-tag issues are reported inside the `%Eipex.Tag{}`
  results (`error: {:cip, status_name, extended}` or another decode reason).
  """
  @spec read(GenServer.server(), String.t() | [String.t()], keyword()) ::
          {:ok, Eipex.Tag.t() | [Eipex.Tag.t()]} | {:error, term()}
  def read(server, name_or_names, opts \\ [])

  def read(server, name, opts) when is_binary(name) do
    read_one(server, name, opts, templates_of(opts))
  end

  def read(server, names, opts) when is_list(names) do
    templates = templates_of(opts)
    connection_size = Keyword.get(opts, :connection_size, @default_connection_size)
    catalog = opts[:tags]

    indexed = Enum.with_index(names)

    {oversized, batchable} =
      Enum.split_with(indexed, fn {name, _index} ->
        tag_estimate(name, catalog) > connection_size
      end)

    batches = batch_by_size(batchable, catalog, connection_size)

    with {:ok, batched} <- read_batches(server, batches, opts, templates),
         {:ok, singles} <- read_each(server, oversized, opts, templates) do
      ordered =
        (batched ++ singles)
        |> Enum.sort_by(&elem(&1, 0))
        |> Enum.map(&elem(&1, 1))

      {:ok, ordered}
    end
  end

  defp templates_of(opts) do
    case opts[:tags] do
      %{templates: templates} -> templates
      _ -> %{}
    end
  end

  # -- Single-tag read + fragmentation ------------------------------------------

  defp read_one(server, name, opts, templates) do
    elements = Keyword.get(opts, :elements, 1)

    case Scanner.generic_message(server,
           service: 0x4C,
           symbolic: name,
           data: <<elements::16-little>>
         ) do
      {:ok, %{status_name: :success, data: data}} ->
        build_tag(name, data, templates)

      {:ok, %{status_name: :partial_transfer, data: first_chunk}} ->
        case read_fragments(server, name, elements, first_chunk) do
          {:ok, full} ->
            build_tag(name, full, templates)

          {:cip_error, status_name, extended} ->
            {:ok, error_tag(name, {:cip, status_name, extended})}

          {:malformed, reason} ->
            {:ok, error_tag(name, reason)}

          {:transport_error, reason} ->
            {:error, reason}
        end

      {:ok, %{status_name: status_name, extended: extended}} ->
        {:ok, error_tag(name, {:cip, status_name, extended})}

      {:error, _} = error ->
        error
    end
  end

  # A genuine `:partial_transfer` continuation must carry the repeated
  # header plus at least one new payload byte — otherwise there's no
  # progress and, left unguarded, the loop below would spin forever
  # requesting the same offset (the class of bug already found and fixed
  # twice in `tag_list/2`'s symbol-list and template-fetch loops). Devices
  # don't do this; malformed/degenerate replies still must not crash or
  # hang the caller.
  defp read_fragments(server, name, elements, first_chunk) do
    header_len = header_length(first_chunk)

    if byte_size(first_chunk) > header_len do
      <<header::binary-size(header_len), payload::binary>> = first_chunk
      fragment_loop(server, name, elements, header, byte_size(payload), payload)
    else
      {:malformed, :malformed_fragment_reply}
    end
  end

  defp fragment_loop(server, name, elements, header, offset, acc) do
    header_len = byte_size(header)

    case Scanner.generic_message(server,
           service: 0x52,
           symbolic: name,
           data: <<elements::16-little, offset::32-little>>
         ) do
      {:ok, %{status_name: :success, data: chunk}} when byte_size(chunk) >= header_len ->
        {:ok, header <> acc <> strip_header(chunk, header_len)}

      {:ok, %{status_name: :partial_transfer, data: chunk}} when byte_size(chunk) > header_len ->
        payload = strip_header(chunk, header_len)
        fragment_loop(server, name, elements, header, offset + byte_size(payload), acc <> payload)

      {:ok, %{status_name: status_name}} when status_name in [:success, :partial_transfer] ->
        {:malformed, :malformed_fragment_reply}

      {:ok, %{status_name: status_name, extended: extended}} ->
        {:cip_error, status_name, extended}

      {:error, reason} ->
        {:transport_error, reason}
    end
  end

  defp strip_header(chunk, len), do: binary_part(chunk, len, byte_size(chunk) - len)

  defp header_length(<<0xA0, 0x02, _rest::binary>>), do: 4
  defp header_length(_), do: 2

  defp build_tag(name, data, templates) do
    case Value.decode_reply(data, templates) do
      {:ok, value} ->
        {:ok, %Eipex.Tag{name: name, value: value, type: reply_type(data), error: nil}}

      {:error, reason} ->
        {:ok, error_tag(name, reason)}
    end
  end

  defp reply_type(<<0xA0, 0x02, handle::16-little, _rest::binary>>), do: {:struct, handle}
  defp reply_type(<<code::16-little, _rest::binary>>), do: Types.type_name(code)
  defp reply_type(_), do: :unknown

  defp error_tag(name, reason), do: %Eipex.Tag{name: name, value: nil, type: nil, error: reason}

  # -- Bulk read: Multiple Service Packet batching ------------------------------

  defp batch_by_size(indexed, catalog, connection_size) do
    {done, current, _sum} =
      Enum.reduce(indexed, {[], [], 0}, fn {name, _index} = item, {done, current, sum} ->
        size = tag_estimate(name, catalog)

        cond do
          current == [] -> {done, [item], size}
          sum + size <= connection_size -> {done, [item | current], sum + size}
          true -> {done ++ [Enum.reverse(current)], [item], size}
        end
      end)

    if current == [], do: done, else: done ++ [Enum.reverse(current)]
  end

  defp read_batches(server, batches, opts, templates) do
    Enum.reduce_while(batches, {:ok, []}, fn batch, {:ok, acc} ->
      case read_batch(server, batch, opts, templates) do
        {:ok, tags} -> {:cont, {:ok, acc ++ tags}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp read_batch(server, batch, opts, templates) do
    elements = Keyword.get(opts, :elements, 1)

    sub_reads =
      Enum.map(batch, fn {name, _index} ->
        LogixCodec.encode_read_tag([symbolic: name], elements)
      end)

    data = LogixCodec.multiple_service_data(sub_reads)

    case Scanner.generic_message(server,
           service: 0x0A,
           path: @multiple_service_path,
           data: data
         ) do
      {:ok, %{status_name: :success, data: reply_data}} ->
        case LogixCodec.decode_multiple_service_reply(reply_data) do
          {:ok, sub_replies} -> decode_batch(server, batch, sub_replies, opts, templates)
          {:error, reason} -> {:ok, tag_errors(batch, reason)}
        end

      {:ok, %{status_name: status_name, extended: extended}} ->
        {:ok, tag_errors(batch, {:cip, status_name, extended})}

      {:error, _} = error ->
        error
    end
  end

  defp tag_errors(batch, reason) do
    Enum.map(batch, fn {name, index} -> {index, error_tag(name, reason)} end)
  end

  defp decode_batch(server, batch, sub_replies, opts, templates) do
    if length(batch) == length(sub_replies) do
      batch
      |> Enum.zip(sub_replies)
      |> Enum.reduce_while({:ok, []}, fn {{name, index}, sub_reply}, {:ok, acc} ->
        case decode_sub_reply(server, name, sub_reply, opts, templates) do
          {:ok, tag} -> {:cont, {:ok, [{index, tag} | acc]}}
          {:error, _} = error -> {:halt, error}
        end
      end)
      |> case do
        {:ok, tags} -> {:ok, Enum.reverse(tags)}
        error -> error
      end
    else
      {:ok, tag_errors(batch, :malformed_msp)}
    end
  end

  defp decode_sub_reply(server, name, sub_reply, opts, templates) do
    case MessageRouter.decode_response(sub_reply) do
      {:ok, %{status_name: :success, data: data}} ->
        build_tag(name, data, templates)

      {:ok, %{status_name: :partial_transfer}} ->
        read_one(server, name, opts, templates)

      {:ok, %{status_name: status_name, extended: extended}} ->
        {:ok, error_tag(name, {:cip, status_name, extended})}

      {:error, reason} ->
        {:ok, error_tag(name, reason)}
    end
  end

  defp read_each(server, indexed, opts, templates) do
    indexed
    |> Enum.reduce_while({:ok, []}, fn {name, index}, {:ok, acc} ->
      case read_one(server, name, opts, templates) do
        {:ok, tag} -> {:cont, {:ok, [{index, tag} | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, tags} -> {:ok, Enum.reverse(tags)}
      error -> error
    end
  end

  # -- Size estimation for MSP batching -----------------------------------------

  defp tag_estimate(name, %{tags: tags, templates: templates}) do
    case Enum.find(tags, &(&1.name == name)) do
      nil -> @default_tag_estimate
      tag -> type_estimate(tag.type, templates)
    end
  end

  defp tag_estimate(_name, _catalog), do: @default_tag_estimate

  defp type_estimate({:struct, handle}, templates) do
    case Map.fetch(templates, handle) do
      {:ok, %{structure_size: size}} -> size + 4
      :error -> @default_tag_estimate
    end
  end

  defp type_estimate({:array, _base, _dims}, _templates), do: @default_tag_estimate

  defp type_estimate(atomic, _templates) when is_atom(atomic) do
    (element_byte_size(atomic) || 4) + 2
  end

  defp element_byte_size(name) when name in [:bool, :sint, :usint, :byte], do: 1
  defp element_byte_size(name) when name in [:int, :uint, :word], do: 2
  defp element_byte_size(name) when name in [:dint, :udint, :dword, :real], do: 4
  defp element_byte_size(name) when name in [:lint, :ulint, :lword, :lreal], do: 8
  defp element_byte_size(_name), do: nil
end
