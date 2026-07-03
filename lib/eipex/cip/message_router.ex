defmodule Eipex.CIP.MessageRouter do
  @moduledoc """
  CIP Message Router request/response framing and the general status table.
  Request: service, path size (words), padded EPATH, service data.
  Response: service | 0x80, reserved 0, general status, extended words, data.
  """

  alias Eipex.CIP.Path

  @statuses %{
    0x00 => :success,
    0x01 => :connection_failure,
    0x02 => :resource_unavailable,
    0x03 => :invalid_parameter_value,
    0x04 => :path_segment_error,
    0x05 => :path_destination_unknown,
    0x06 => :partial_transfer,
    0x07 => :connection_lost,
    0x08 => :service_not_supported,
    0x09 => :invalid_attribute_value,
    0x0A => :attribute_list_error,
    0x0B => :already_in_state,
    0x0C => :object_state_conflict,
    0x0D => :object_already_exists,
    0x0E => :attribute_not_settable,
    0x0F => :privilege_violation,
    0x10 => :device_state_conflict,
    0x11 => :reply_data_too_large,
    0x13 => :not_enough_data,
    0x14 => :attribute_not_supported,
    0x15 => :too_much_data,
    0x16 => :object_does_not_exist,
    0x1E => :embedded_service_error,
    0x1F => :vendor_specific_error,
    0x20 => :invalid_parameter,
    0x26 => :path_size_invalid,
    0x2C => :attribute_not_gettable,
    0xFF => :general_error
  }

  @spec encode_request(byte(), binary() | [Path.segment()], binary()) :: binary()
  def encode_request(service, path, data \\ <<>>)

  def encode_request(service, path, data) when is_list(path),
    do: encode_request(service, Path.encode(path), data)

  def encode_request(service, path, data) when is_binary(path) do
    <<service, Path.words(path), path::binary, data::binary>>
  end

  @spec decode_request(binary()) ::
          {:ok, %{service: byte(), path: binary(), data: binary()}}
          | {:error, :malformed_request}
  def decode_request(<<service, words, path::binary-size(words * 2), data::binary>>) do
    {:ok, %{service: service, path: path, data: data}}
  end

  def decode_request(_), do: {:error, :malformed_request}

  @spec encode_response(byte(), byte(), keyword()) :: binary()
  def encode_response(service, status, opts \\ []) do
    data = Keyword.get(opts, :data, <<>>)
    extended = Keyword.get(opts, :extended, [])
    ext_bin = for word <- extended, into: <<>>, do: <<word::16-little>>

    <<Bitwise.bor(service, 0x80), 0x00, status, length(extended), ext_bin::binary, data::binary>>
  end

  @spec decode_response(binary()) ::
          {:ok,
           %{
             service: byte(),
             status: byte(),
             status_name: atom(),
             extended: [non_neg_integer()],
             data: binary()
           }}
          | {:error, :malformed_response}
  def decode_response(
        <<reply_service, 0x00, status, ext_words, ext::binary-size(ext_words * 2), data::binary>>
      ) do
    extended = for <<word::16-little <- ext>>, do: word

    {:ok,
     %{
       service: Bitwise.band(reply_service, 0x7F),
       status: status,
       status_name: status_name(status),
       extended: extended,
       data: data
     }}
  end

  def decode_response(_), do: {:error, :malformed_response}

  @spec status_name(byte()) :: atom()
  def status_name(code), do: Map.get(@statuses, code, :unknown)
end
