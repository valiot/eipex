defmodule Eipex.Encap do
  @moduledoc """
  EtherNet/IP encapsulation layer codec: the fixed 24-byte header and its
  commands (CIP Vol 2). All fields little-endian.
  """

  defstruct command: nil,
            session_handle: 0,
            status: 0,
            sender_context: <<0::64>>,
            options: 0,
            data: <<>>

  @type t :: %__MODULE__{}

  @commands [
    nop: 0x0000,
    list_services: 0x0004,
    list_identity: 0x0063,
    list_interfaces: 0x0064,
    register_session: 0x0065,
    unregister_session: 0x0066,
    send_rr_data: 0x006F,
    send_unit_data: 0x0070
  ]

  @statuses %{
    0x0000 => :success,
    0x0001 => :invalid_command,
    0x0002 => :insufficient_memory,
    0x0003 => :incorrect_data,
    0x0064 => :invalid_session_handle,
    0x0065 => :invalid_length,
    0x0069 => :unsupported_protocol_version
  }

  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = frame) do
    code = Keyword.fetch!(@commands, frame.command)

    <<code::16-little, byte_size(frame.data)::16-little, frame.session_handle::32-little,
      frame.status::32-little, frame.sender_context::binary-size(8), frame.options::32-little,
      frame.data::binary>>
  end

  @spec decode(binary()) ::
          {:ok, t(), binary()} | :partial | {:error, {:unknown_command, integer()}}
  def decode(
        <<code::16-little, length::16-little, session::32-little, status::32-little,
          context::binary-size(8), options::32-little, rest::binary>>
      ) do
    case {command_name(code), rest} do
      {nil, _} ->
        {:error, {:unknown_command, code}}

      {command, <<data::binary-size(length), tail::binary>>} ->
        {:ok,
         %__MODULE__{
           command: command,
           session_handle: session,
           status: status,
           sender_context: context,
           options: options,
           data: data
         }, tail}

      _short ->
        :partial
    end
  end

  def decode(bin) when is_binary(bin), do: :partial

  @spec status_name(non_neg_integer()) :: atom()
  def status_name(code), do: Map.get(@statuses, code, :unknown)

  defp command_name(code) do
    Enum.find_value(@commands, fn {name, c} -> if c == code, do: name end)
  end
end
