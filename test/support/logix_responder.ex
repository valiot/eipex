defmodule Eipex.TestSupport.LogixResponder do
  @moduledoc """
  A `ScriptedTarget` handler factory that speaks the Logix data-access
  subset — Symbol Object discovery, Template Object fetch, atomic tag
  read/write, and Multiple Service Packet dispatch — using the real
  `Eipex.CIP` codecs. Not a mock: every reply is decoded from and built with
  the same wire format the scanner uses, from a small canned `spec`.

  `spec` is a map:

    * `:symbols` — `[%{instance, name, raw_type}]`, the Symbol Object
      catalog, given in ascending instance order.
    * `:chunk_size` — max symbols returned per Get_Instance_Attribute_List
      reply (defaults to the whole catalog in one reply).
    * `:templates` — `%{template_instance => udt/1 output}`.
    * `:template_chunk_size` — max bytes returned per Read Template reply
      fragment (defaults to the whole definition in one reply).
    * `:tags` — `%{name => {type_atom, value}}`, the mutable atomic tag
      store backing symbolic read/write (defaults to `%{}`).

  Reused unchanged by the read and write task suites that build on
  `tag_list/2`.
  """

  alias Eipex.CIP.{Logix, MessageRouter, Path, Types}

  @template_class 0x6C

  @doc """
  Builds a canned Template object definition from a friendly member list, as
  if fetched from a real controller.

  `members` is `[{name, type_atom, offset}]`; each becomes a scalar member
  (BOOL members default to bit 0 of their byte). Returns
  `%{attrs: %{handle, member_count, definition_size, structure_size},
  definition_binary: binary}` — the shape the Template Object handlers below
  serve directly.
  """
  @spec udt(keyword()) :: map()
  def udt(opts) do
    handle = Keyword.fetch!(opts, :handle)
    name = Keyword.fetch!(opts, :name)
    members = Keyword.fetch!(opts, :members)
    structure_size = Keyword.fetch!(opts, :structure_size)

    meta =
      for {_name, type, offset} <- members, into: <<>> do
        <<0::16-little, Types.type_code(type)::16-little, offset::32-little>>
      end

    names = Enum.map_join([name | Enum.map(members, &elem(&1, 0))], <<0>>, & &1)
    definition = pad_for_definition_size(meta <> names <> <<0>>)

    %{
      attrs: %{
        handle: handle,
        member_count: length(members),
        definition_size: div(byte_size(definition) + 23, 4),
        structure_size: structure_size
      },
      definition_binary: definition
    }
  end

  # Read Template's byte accounting is `definition_size * 4 - 23`; pad with
  # trailing NULs (harmless — decode_template_definition's name splitter
  # trims empty tokens) so that formula lands exactly on the real length.
  defp pad_for_definition_size(binary) do
    case rem(byte_size(binary) + 23, 4) do
      0 -> binary
      remainder -> binary <> :binary.copy(<<0>>, 4 - remainder)
    end
  end

  @doc "Builds a ScriptedTarget handler that answers from `spec`."
  @spec handler(map()) :: (binary() -> binary() | :no_reply)
  def handler(spec) do
    {:ok, agent} = Agent.start_link(fn -> Map.get(spec, :tags, %{}) end)

    fn mr_request ->
      {:ok, %{service: service, path: path, data: data}} =
        MessageRouter.decode_request(mr_request)

      dispatch(service, path, data, spec, agent)
    end
  end

  # -- Dispatch ------------------------------------------------------------

  defp dispatch(0x55, path, data, spec, _agent), do: symbol_list_reply(path, data, spec)
  defp dispatch(0x03, path, data, spec, _agent), do: template_attrs_reply(path, data, spec)

  defp dispatch(0x4C, path, data, spec, agent) do
    if template_path?(path) do
      read_template_reply(path, data, spec)
    else
      read_tag_reply(path, data, agent)
    end
  end

  defp dispatch(0x4D, path, data, _spec, agent), do: write_tag_reply(path, data, agent)
  defp dispatch(0x0A, _path, data, spec, agent), do: multiple_service_reply(data, spec, agent)

  defp dispatch(service, _path, _data, _spec, _agent),
    do: MessageRouter.encode_response(service, 0x08)

  defp template_path?(path) do
    case Path.decode(path) do
      {:ok, segments} -> Keyword.get(segments, :class) == @template_class
      _ -> false
    end
  end

  defp path_instance(path) do
    {:ok, segments} = Path.decode(path)
    Keyword.fetch!(segments, :instance)
  end

  defp path_symbolic(path) do
    {:ok, segments} = Path.decode(path)
    Keyword.fetch!(segments, :symbolic)
  end

  # -- Symbol Object (service 0x55) --------------------------------------------

  defp symbol_list_reply(path, _data, spec) do
    start = path_instance(path)
    symbols = Map.fetch!(spec, :symbols)
    chunk_size = Map.get(spec, :chunk_size, length(symbols))

    remaining = Enum.filter(symbols, &(&1.instance >= start))
    {chunk, rest} = Enum.split(remaining, chunk_size)

    body =
      for %{instance: instance, name: name, raw_type: raw_type} <- chunk, into: <<>> do
        <<instance::32-little, byte_size(name)::16-little, name::binary, raw_type::16-little>>
      end

    status = if rest == [], do: 0x00, else: 0x06
    MessageRouter.encode_response(0x55, status, data: body)
  end

  # -- Template Object (class 0x6C) --------------------------------------------

  @attr_sizes %{1 => 2, 2 => 2, 4 => 4, 5 => 4}
  @attr_keys %{1 => :handle, 2 => :member_count, 4 => :definition_size, 5 => :structure_size}

  defp template_attrs_reply(path, <<count::16-little, ids_bin::binary>>, spec) do
    template_instance = path_instance(path)
    ids = for <<id::16-little <- ids_bin>>, do: id

    case Map.fetch(spec.templates, template_instance) do
      {:ok, %{attrs: attrs}} ->
        body =
          for id <- Enum.take(ids, count), into: <<>> do
            value = Map.fetch!(attrs, Map.fetch!(@attr_keys, id))
            size = Map.fetch!(@attr_sizes, id)
            <<id::16-little, 0::16-little, value::little-size(size * 8)>>
          end

        MessageRouter.encode_response(0x03, 0x00, data: <<count::16-little, body::binary>>)

      :error ->
        MessageRouter.encode_response(0x03, 0x16)
    end
  end

  defp read_template_reply(path, <<offset::32-little, bytes::16-little>>, spec) do
    template_instance = path_instance(path)

    case Map.fetch(spec.templates, template_instance) do
      {:ok, %{definition_binary: definition}} ->
        max_chunk = Map.get(spec, :template_chunk_size, byte_size(definition))
        remaining = byte_size(definition) - offset
        take = Enum.min([bytes, remaining, max_chunk])
        chunk = binary_part(definition, offset, take)
        status = if offset + take == byte_size(definition), do: 0x00, else: 0x06
        MessageRouter.encode_response(0x4C, status, data: chunk)

      :error ->
        MessageRouter.encode_response(0x4C, 0x16)
    end
  end

  # -- Tag read/write (symbolic paths) -----------------------------------------

  defp read_tag_reply(path, <<_elements::16-little>>, agent) do
    name = path_symbolic(path)

    case Agent.get(agent, &Map.fetch(&1, name)) do
      {:ok, {type, value}} ->
        {:ok, encoded} = Types.encode(type, value)

        MessageRouter.encode_response(0x4C, 0x00,
          data: <<Types.type_code(type)::16-little, encoded::binary>>
        )

      :error ->
        MessageRouter.encode_response(0x4C, 0x16)
    end
  end

  defp write_tag_reply(path, <<type_code::16-little, _elements::16-little, bytes::binary>>, agent) do
    name = path_symbolic(path)
    type = Types.type_name(type_code)

    case Agent.get(agent, &Map.fetch(&1, name)) do
      {:ok, {^type, _current}} ->
        case Types.decode(type, bytes) do
          {:ok, value} ->
            Agent.update(agent, &Map.put(&1, name, {type, value}))
            MessageRouter.encode_response(0x4D, 0x00)

          {:error, _} ->
            MessageRouter.encode_response(0x4D, 0xFF, extended: [0x2107])
        end

      {:ok, {_other_type, _current}} ->
        MessageRouter.encode_response(0x4D, 0xFF, extended: [0x2107])

      :error ->
        MessageRouter.encode_response(0x4D, 0x16)
    end
  end

  # -- Multiple Service Packet (service 0x0A) ----------------------------------

  defp multiple_service_reply(data, spec, agent) do
    {:ok, requests} = Logix.decode_multiple_service_reply(data)

    replies =
      for request <- requests do
        {:ok, %{service: service, path: path, data: sub_data}} =
          MessageRouter.decode_request(request)

        dispatch(service, path, sub_data, spec, agent)
      end

    MessageRouter.encode_response(0x0A, 0x00, data: Logix.multiple_service_data(replies))
  end
end
