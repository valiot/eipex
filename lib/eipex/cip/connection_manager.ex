defmodule Eipex.CIP.ConnectionManager do
  @moduledoc """
  Connection Manager (class 0x06) service codecs: Forward Open (0x54),
  Large Forward Open (0x5B), Forward Close (0x4E), Unconnected Send (0x52).
  RPIs are in microseconds (trap #11).
  """

  import Bitwise

  alias Eipex.CIP.{MessageRouter, Path}

  @cm_path [class: 0x06, instance: 0x01]

  defmodule ForwardOpen do
    defstruct priority_time_tick: 0x0A,
              timeout_ticks: 5,
              o2t_connection_id: 0,
              t2o_connection_id: 0,
              connection_serial: 0,
              originator_vendor_id: 0,
              originator_serial: 0,
              timeout_multiplier: 1,
              o2t_rpi: 1_000_000,
              o2t_params: nil,
              t2o_rpi: 1_000_000,
              t2o_params: nil,
              transport: nil,
              connection_path: <<>>

    @type t :: %__MODULE__{}
  end

  defmodule ForwardOpenReply do
    defstruct o2t_connection_id: 0,
              t2o_connection_id: 0,
              connection_serial: 0,
              originator_vendor_id: 0,
              originator_serial: 0,
              o2t_api: 0,
              t2o_api: 0,
              application_reply: <<>>

    @type t :: %__MODULE__{}
  end

  @ext_statuses %{
    0x0100 => :connection_in_use,
    0x0106 => :ownership_conflict,
    0x0110 => :target_not_configured,
    0x0111 => :rpi_not_supported,
    0x0113 => :out_of_connections,
    0x0123 => :invalid_o2t_type,
    0x0124 => :invalid_t2o_type,
    0x0127 => :invalid_o2t_size,
    0x0128 => :invalid_t2o_size,
    0x0129 => :invalid_config_path,
    0x012A => :invalid_consuming_path,
    0x012B => :invalid_producing_path,
    0x0315 => :invalid_segment_type
  }

  # -- Network connection parameters ------------------------------------------

  @conn_types [null: 0, multicast: 1, point_to_point: 2]
  @priorities [low: 0, high: 1, scheduled: 2, urgent: 3]

  @spec encode_params(:standard | :large, map()) :: binary()
  def encode_params(:standard, p) do
    value =
      owner_bit(p.owner) <<< 15 ||| Keyword.fetch!(@conn_types, p.type) <<< 13 |||
        Keyword.fetch!(@priorities, p.priority) <<< 10 |||
        size_bit(p.size_type) <<< 9 ||| (p.size &&& 0x1FF)

    <<value::16-little>>
  end

  def encode_params(:large, p) do
    value =
      owner_bit(p.owner) <<< 31 ||| Keyword.fetch!(@conn_types, p.type) <<< 29 |||
        Keyword.fetch!(@priorities, p.priority) <<< 26 |||
        size_bit(p.size_type) <<< 25 ||| (p.size &&& 0xFFFF)

    <<value::32-little>>
  end

  @spec decode_params(:standard | :large, binary()) :: map()
  def decode_params(:standard, <<value::16-little>>) do
    %{
      owner: owner_name(value >>> 15 &&& 1),
      type: conn_type_name(value >>> 13 &&& 0x3),
      priority: priority_name(value >>> 10 &&& 0x3),
      size_type: size_name(value >>> 9 &&& 1),
      size: value &&& 0x1FF
    }
  end

  def decode_params(:large, <<value::32-little>>) do
    %{
      owner: owner_name(value >>> 31 &&& 1),
      type: conn_type_name(value >>> 29 &&& 0x3),
      priority: priority_name(value >>> 26 &&& 0x3),
      size_type: size_name(value >>> 25 &&& 1),
      size: value &&& 0xFFFF
    }
  end

  defp owner_bit(:exclusive), do: 0
  defp owner_bit(:redundant), do: 1
  defp owner_name(0), do: :exclusive
  defp owner_name(1), do: :redundant
  defp size_bit(:fixed), do: 0
  defp size_bit(:variable), do: 1
  defp size_name(0), do: :fixed
  defp size_name(1), do: :variable

  defp conn_type_name(v), do: Enum.find_value(@conn_types, fn {n, c} -> if c == v, do: n end)
  defp priority_name(v), do: Enum.find_value(@priorities, fn {n, c} -> if c == v, do: n end)

  # -- Transport class/trigger -------------------------------------------------

  @triggers [cyclic: 0, change_of_state: 1, application: 2]

  @spec encode_transport(map()) :: binary()
  def encode_transport(%{direction: dir, trigger: trigger, class: class}) do
    dir_bit = if dir == :server, do: 1, else: 0
    <<dir_bit <<< 7 ||| Keyword.fetch!(@triggers, trigger) <<< 4 ||| class>>
  end

  @spec decode_transport(binary()) :: map()
  def decode_transport(<<byte>>) do
    %{
      direction: if((byte &&& 0x80) != 0, do: :server, else: :client),
      trigger: Enum.find_value(@triggers, fn {n, c} -> if c == (byte >>> 4 &&& 0x7), do: n end),
      class: byte &&& 0xF
    }
  end

  # -- Forward Open ------------------------------------------------------------

  @spec encode_forward_open(ForwardOpen.t(), :standard | :large) :: binary()
  def encode_forward_open(%ForwardOpen{} = fo, variant) do
    service = if variant == :standard, do: 0x54, else: 0x5B

    data =
      <<fo.priority_time_tick, fo.timeout_ticks, fo.o2t_connection_id::32-little,
        fo.t2o_connection_id::32-little, fo.connection_serial::16-little,
        fo.originator_vendor_id::16-little, fo.originator_serial::32-little,
        fo.timeout_multiplier, 0, 0, 0, fo.o2t_rpi::32-little,
        encode_params(variant, fo.o2t_params)::binary, fo.t2o_rpi::32-little,
        encode_params(variant, fo.t2o_params)::binary, encode_transport(fo.transport)::binary,
        Path.words(fo.connection_path), fo.connection_path::binary>>

    MessageRouter.encode_request(service, @cm_path, data)
  end

  @spec decode_forward_open(0x54 | 0x5B, binary()) ::
          {:ok, ForwardOpen.t()} | {:error, :malformed_forward_open}
  def decode_forward_open(service, data) when service in [0x54, 0x5B] do
    {variant, params_size} = if service == 0x54, do: {:standard, 2}, else: {:large, 4}

    with <<ptt, ticks, o2t_id::32-little, t2o_id::32-little, serial::16-little, vendor::16-little,
           orig_serial::32-little, multiplier, _::24, o2t_rpi::32-little,
           o2t_p::binary-size(params_size), t2o_rpi::32-little, t2o_p::binary-size(params_size),
           transport::binary-size(1), path_words, path::binary-size(path_words * 2)>> <- data do
      {:ok,
       %ForwardOpen{
         priority_time_tick: ptt,
         timeout_ticks: ticks,
         o2t_connection_id: o2t_id,
         t2o_connection_id: t2o_id,
         connection_serial: serial,
         originator_vendor_id: vendor,
         originator_serial: orig_serial,
         timeout_multiplier: multiplier,
         o2t_rpi: o2t_rpi,
         o2t_params: decode_params(variant, o2t_p),
         t2o_rpi: t2o_rpi,
         t2o_params: decode_params(variant, t2o_p),
         transport: decode_transport(transport),
         connection_path: path
       }}
    else
      _ -> {:error, :malformed_forward_open}
    end
  end

  @spec encode_forward_open_reply(ForwardOpenReply.t()) :: binary()
  def encode_forward_open_reply(%ForwardOpenReply{} = r) do
    reply_words = div(byte_size(r.application_reply), 2)

    <<r.o2t_connection_id::32-little, r.t2o_connection_id::32-little,
      r.connection_serial::16-little, r.originator_vendor_id::16-little,
      r.originator_serial::32-little, r.o2t_api::32-little, r.t2o_api::32-little, reply_words, 0,
      r.application_reply::binary>>
  end

  @spec decode_forward_open_reply(binary()) ::
          {:ok, ForwardOpenReply.t()} | {:error, :malformed_reply}
  def decode_forward_open_reply(
        <<o2t::32-little, t2o::32-little, serial::16-little, vendor::16-little,
          orig_serial::32-little, o2t_api::32-little, t2o_api::32-little, reply_words, _reserved,
          reply::binary-size(reply_words * 2)>>
      ) do
    {:ok,
     %ForwardOpenReply{
       o2t_connection_id: o2t,
       t2o_connection_id: t2o,
       connection_serial: serial,
       originator_vendor_id: vendor,
       originator_serial: orig_serial,
       o2t_api: o2t_api,
       t2o_api: t2o_api,
       application_reply: reply
     }}
  end

  def decode_forward_open_reply(_), do: {:error, :malformed_reply}

  # -- Forward Close -----------------------------------------------------------

  @spec encode_forward_close(map(), binary(), keyword()) :: binary()
  def encode_forward_close(triad, connection_path, opts) do
    data =
      <<Keyword.get(opts, :priority_time_tick, 0x0A), Keyword.get(opts, :timeout_ticks, 5),
        triad.connection_serial::16-little, triad.originator_vendor_id::16-little,
        triad.originator_serial::32-little, Path.words(connection_path), 0,
        connection_path::binary>>

    MessageRouter.encode_request(0x4E, @cm_path, data)
  end

  @spec decode_forward_close(binary()) :: {:ok, map()} | {:error, :malformed_forward_close}
  def decode_forward_close(
        <<_ptt, _ticks, serial::16-little, vendor::16-little, orig_serial::32-little, path_words,
          _reserved, path::binary-size(path_words * 2)>>
      ) do
    {:ok,
     %{
       connection_serial: serial,
       originator_vendor_id: vendor,
       originator_serial: orig_serial,
       connection_path: path
     }}
  end

  def decode_forward_close(_), do: {:error, :malformed_forward_close}

  # -- Unconnected Send --------------------------------------------------------

  @spec encode_unconnected_send(binary(), [Path.segment()], keyword()) :: binary()
  def encode_unconnected_send(embedded, route_path, opts) do
    pad = if rem(byte_size(embedded), 2) == 1, do: <<0x00>>, else: <<>>
    route = Path.encode(route_path)

    data =
      <<Keyword.get(opts, :priority_time_tick, 0x0A), Keyword.get(opts, :timeout_ticks, 5),
        byte_size(embedded)::16-little, embedded::binary, pad::binary, Path.words(route), 0x00,
        route::binary>>

    MessageRouter.encode_request(0x52, @cm_path, data)
  end

  # -- Helpers -----------------------------------------------------------------

  @spec ext_status_name(non_neg_integer()) :: atom()
  def ext_status_name(code), do: Map.get(@ext_statuses, code, :unknown)

  @spec timeout_factor(0..7) :: pos_integer()
  def timeout_factor(code), do: 4 <<< code
end
