defmodule Eipex.Identity do
  @moduledoc """
  The Identity item (type 0x000C) carried in ListIdentity responses.
  sockaddr fields are big-endian (network order); the rest is little-endian.
  """

  defstruct protocol_version: 1,
            ip: {0, 0, 0, 0},
            port: 44_818,
            vendor_id: 0,
            device_type: 0,
            product_code: 0,
            revision: {1, 0},
            status: 0,
            serial_number: 0,
            product_name: "",
            state: 0

  @type t :: %__MODULE__{}

  @spec decode_item(binary()) :: {:ok, t()} | {:error, :malformed_identity}
  def decode_item(
        <<version::16-little, _family::16-big, port::16-big, a, b, c, d, _zero::64,
          vendor::16-little, type::16-little, product::16-little, major, minor, status::16-little,
          serial::32-little, name_len, name::binary-size(name_len), state>>
      ) do
    {:ok,
     %__MODULE__{
       protocol_version: version,
       ip: {a, b, c, d},
       port: port,
       vendor_id: vendor,
       device_type: type,
       product_code: product,
       revision: {major, minor},
       status: status,
       serial_number: serial,
       product_name: name,
       state: state
     }}
  end

  def decode_item(_), do: {:error, :malformed_identity}

  @spec encode_item(t()) :: binary()
  def encode_item(%__MODULE__{ip: {a, b, c, d}, revision: {major, minor}} = id) do
    <<id.protocol_version::16-little, 2::16-big, id.port::16-big, a, b, c, d, 0::64,
      id.vendor_id::16-little, id.device_type::16-little, id.product_code::16-little, major,
      minor, id.status::16-little, id.serial_number::32-little, byte_size(id.product_name),
      id.product_name::binary, id.state>>
  end
end
