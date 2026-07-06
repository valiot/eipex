defmodule Eipex.IO do
  @moduledoc """
  Pure helpers for class 1 implicit I/O: sequence arithmetic with wraparound,
  RPI conversion, and the UDP packet framing (CPF Sequenced Address +
  Connected Data with 16-bit sequence count and optional 32-bit run/idle
  header).
  """

  alias Eipex.CPF

  @mod32 0x1_0000_0000

  @spec seq_newer?(non_neg_integer(), non_neg_integer()) :: boolean()
  def seq_newer?(a, b) do
    diff = rem(a - b + @mod32, @mod32)
    diff in 1..0x7FFF_FFFF
  end

  @spec next_seq16(non_neg_integer()) :: 0..0xFFFF
  def next_seq16(n), do: rem(n + 1, 0x10000)

  @spec next_seq32(non_neg_integer()) :: non_neg_integer()
  def next_seq32(n), do: rem(n + 1, @mod32)

  @spec wire_size(non_neg_integer(), boolean()) :: pos_integer()
  def wire_size(data_size, run_idle?), do: data_size + 2 + if(run_idle?, do: 4, else: 0)

  @spec rpi_ms(pos_integer()) :: pos_integer()
  def rpi_ms(rpi_us), do: max(1, div(rpi_us, 1000))

  @spec encode_packet(
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          nil | :run | :idle,
          binary()
        ) :: binary()
  def encode_packet(conn_id, seq32, seq16, run_idle, data) do
    header =
      case run_idle do
        nil -> <<>>
        :run -> <<1::32-little>>
        :idle -> <<0::32-little>>
      end

    CPF.encode([
      {:sequenced_address, conn_id, seq32},
      {:connected_data, <<seq16::16-little, header::binary, data::binary>>}
    ])
  end

  @spec decode_packet(binary(), boolean()) ::
          {:ok,
           %{
             conn_id: non_neg_integer(),
             seq32: non_neg_integer(),
             seq16: non_neg_integer(),
             run: nil | :run | :idle,
             data: binary()
           }}
          | :error
  def decode_packet(datagram, run_idle?) do
    with {:ok, items} <- CPF.decode(datagram),
         [{:sequenced_address, conn_id, seq32}] <-
           for({:sequenced_address, _, _} = i <- items, do: i),
         [{:connected_data, payload}] <-
           for({:connected_data, _} = i <- items, do: i),
         {:ok, seq16, run, data} <- split_payload(payload, run_idle?) do
      {:ok, %{conn_id: conn_id, seq32: seq32, seq16: seq16, run: run, data: data}}
    else
      _ -> :error
    end
  end

  defp split_payload(<<seq16::16-little, header::32-little, data::binary>>, true) do
    run = if Bitwise.band(header, 1) == 1, do: :run, else: :idle
    {:ok, seq16, run, data}
  end

  defp split_payload(<<seq16::16-little, data::binary>>, false) do
    {:ok, seq16, nil, data}
  end

  defp split_payload(_, _), do: :error
end
