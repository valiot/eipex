defmodule Eipex.Scanner.Logix.ValueTest do
  use ExUnit.Case, async: true

  alias Eipex.Scanner.Logix.Value

  test "decodes atomic scalar and array replies" do
    assert {:ok, 534} = Value.decode_reply(<<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>, %{})
    assert {:ok, [7, 8]} = Value.decode_reply(<<0xC3, 0x00, 7, 0, 8, 0>>, %{})
    assert {:ok, true} = Value.decode_reply(<<0xC1, 0x00, 0xFF>>, %{})
  end

  test "unknown-handle structs pass through raw, not error" do
    reply = <<0xA0, 0x02, 0xAB, 0x0F, 1, 2, 3, 4>>
    assert {:ok, {:struct, 0x0FAB, <<1, 2, 3, 4>>}} = Value.decode_reply(reply, %{})
  end

  test "decodes a flat struct into a member map at member offsets" do
    # UDT with pilot_on(BOOL@0 bit0), count(INT@2), rate(REAL@4)
    template = %{
      name: "MyUDT",
      structure_size: 8,
      members: [
        %{
          name: "pilot_on",
          raw_type: 0x00C1,
          symbol_type: %{atomic_type: :bool, bool_position: 0, structure?: false},
          offset: 0,
          info: 0
        },
        %{
          name: "count",
          raw_type: 0x00C3,
          symbol_type: %{atomic_type: :int, structure?: false},
          offset: 2,
          info: 0
        },
        %{
          name: "rate",
          raw_type: 0x00CA,
          symbol_type: %{atomic_type: :real, structure?: false},
          offset: 4,
          info: 0
        }
      ]
    }

    # body: byte0 = 0x01 (pilot_on true, bit0), bytes2-3 = INT 300, bytes4-7 = REAL 1.5
    body = <<0x01, 0x00, 300::16-little, 1.5::32-little-float>>
    templates = %{0x1111 => template}

    assert {:ok, %{"pilot_on" => true, "count" => 300, "rate" => 1.5}} =
             Value.decode_reply(<<0xA0, 0x02, 0x11, 0x11, body::binary>>, templates)
  end

  test "decodes a Logix STRING struct to an Elixir string" do
    # predefined STRING: LEN(DINT)@0 + DATA(SINT[82])@4, structure_size 88
    template = %{
      name: "STRING",
      structure_size: 88,
      members: [
        %{
          name: "LEN",
          raw_type: 0x00C4,
          symbol_type: %{atomic_type: :dint, structure?: false},
          offset: 0,
          info: 0
        },
        %{
          name: "DATA",
          raw_type: 0x00C2,
          symbol_type: %{atomic_type: :sint, structure?: false},
          offset: 4,
          info: 82
        }
      ]
    }

    text = "hello"
    data = <<byte_size(text)::32-little, text::binary, 0::(82-byte_size(text))*8>>
    templates = %{0x2222 => template}

    assert {:ok, "hello"} =
             Value.decode_reply(<<0xA0, 0x02, 0x22, 0x22, data::binary>>, templates)

    assert Value.string?(template)
  end

  test "encodes atomic values for writes" do
    assert {:ok, {<<0xC4, 0x00>>, <<0x0E, 0x00, 0x00, 0x00>>}} = Value.encode(14, :dint, %{})
    assert {:ok, {<<0xC1, 0x00>>, <<0xFF>>}} = Value.encode(true, :bool, %{})
    assert {:ok, {<<0xC1, 0x00>>, <<0x00>>}} = Value.encode(false, :bool, %{})
    assert {:error, :bad_value} = Value.encode(70_000, :int, %{})
    assert {:error, :struct_write_unsupported} = Value.encode(%{}, {:struct, 1}, %{})
  end
end
