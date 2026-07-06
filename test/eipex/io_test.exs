defmodule Eipex.IOTest do
  use ExUnit.Case, async: true

  alias Eipex.IO

  test "seq_newer? handles monotonic and wraparound cases" do
    assert IO.seq_newer?(2, 1)
    refute IO.seq_newer?(1, 2)
    refute IO.seq_newer?(5, 5)
    # wraparound: 0 is newer than 0xFFFFFFFF
    assert IO.seq_newer?(0, 0xFFFF_FFFF)
    refute IO.seq_newer?(0xFFFF_FFFF, 0)
  end

  test "sequence increments wrap" do
    assert IO.next_seq16(0xFFFF) == 0
    assert IO.next_seq16(5) == 6
    assert IO.next_seq32(0xFFFF_FFFF) == 0
  end

  test "wire_size accounts for seq count and run/idle header" do
    assert IO.wire_size(4, false) == 6
    assert IO.wire_size(4, true) == 10
  end

  test "rpi_ms floors to 1ms" do
    assert IO.rpi_ms(10_000) == 10
    assert IO.rpi_ms(500) == 1
  end

  test "packet round-trips with run/idle header" do
    packet = IO.encode_packet(0xCAFE, 7, 3, :run, <<1, 2, 3, 4>>)

    assert {:ok, %{conn_id: 0xCAFE, seq32: 7, seq16: 3, run: :run, data: <<1, 2, 3, 4>>}} =
             IO.decode_packet(packet, true)

    idle = IO.encode_packet(0xCAFE, 8, 4, :idle, <<0, 0, 0, 0>>)
    assert {:ok, %{run: :idle}} = IO.decode_packet(idle, true)
  end

  test "packet round-trips without run/idle header" do
    packet = IO.encode_packet(0xCAFE, 7, 3, nil, <<9, 9>>)

    assert {:ok, %{conn_id: 0xCAFE, seq32: 7, seq16: 3, run: nil, data: <<9, 9>>}} =
             IO.decode_packet(packet, false)
  end

  test "malformed datagrams decode to :error, never raise" do
    assert :error = IO.decode_packet(<<1, 2, 3>>, true)
    assert :error = IO.decode_packet(:binary.copy(<<0>>, 20), false)
    # run_idle expected but payload too short for the header
    short = IO.encode_packet(1, 1, 1, nil, <<1>>)
    assert :error = IO.decode_packet(short, true)
  end
end
