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

  @typedoc """
  A known command name (e.g. `:register_session`), or `{:unknown, code}` for
  any command code this codec doesn't recognize. Unknown commands still
  decode with the header intact so a caller can reply with encap status
  0x0001 (invalid command) using the same session handle and sender context,
  and resync the stream using the declared length.
  """
  @type command :: atom() | {:unknown, non_neg_integer()}

  @type t :: %__MODULE__{
          command: command() | nil,
          session_handle: non_neg_integer(),
          status: non_neg_integer(),
          sender_context: binary(),
          options: non_neg_integer(),
          data: binary()
        }

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
  def encode(%__MODULE__{} = frame) when byte_size(frame.data) <= 0xFFFF do
    code = Keyword.fetch!(@commands, frame.command)

    <<code::16-little, byte_size(frame.data)::16-little, frame.session_handle::32-little,
      frame.status::32-little, frame.sender_context::binary-size(8), frame.options::32-little,
      frame.data::binary>>
  end

  @spec decode(binary()) :: {:ok, t(), binary()} | :partial
  def decode(
        <<code::16-little, length::16-little, session::32-little, status::32-little,
          context::binary-size(8), options::32-little, rest::binary>>
      ) do
    case {command_name(code) || {:unknown, code}, rest} do
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

  @protocol_version 1

  @spec register_session() :: t()
  def register_session do
    %__MODULE__{command: :register_session, data: <<@protocol_version::16-little, 0::16-little>>}
  end

  @spec unregister_session(non_neg_integer()) :: t()
  def unregister_session(session_handle) do
    %__MODULE__{command: :unregister_session, session_handle: session_handle}
  end

  @spec nop() :: t()
  def nop, do: %__MODULE__{command: :nop}

  @spec list_identity() :: t()
  def list_identity, do: %__MODULE__{command: :list_identity}

  @spec send_rr_data(non_neg_integer(), binary(), non_neg_integer()) :: t()
  def send_rr_data(session_handle, cpf, timeout \\ 0) do
    %__MODULE__{
      command: :send_rr_data,
      session_handle: session_handle,
      data: <<0::32-little, timeout::16-little, cpf::binary>>
    }
  end

  @spec send_unit_data(non_neg_integer(), binary()) :: t()
  def send_unit_data(session_handle, cpf) do
    %__MODULE__{
      command: :send_unit_data,
      session_handle: session_handle,
      data: <<0::32-little, 0::16-little, cpf::binary>>
    }
  end

  @spec unwrap_cpf(t()) :: {:ok, binary()} | {:error, :bad_interface_data}
  def unwrap_cpf(%__MODULE__{data: <<_iface::32, _timeout::16, cpf::binary>>}), do: {:ok, cpf}
  def unwrap_cpf(%__MODULE__{}), do: {:error, :bad_interface_data}
end
