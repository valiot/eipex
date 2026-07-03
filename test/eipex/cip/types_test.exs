defmodule Eipex.CIP.TypesTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.Types

  test "type codes match the CIP table" do
    assert Types.type_code(:dint) == 0xC4
    assert Types.type_code(:real) == 0xCA
    assert Types.type_name(0xC3) == :int
    assert Types.type_name(0x1234) == :unknown
  end

  test "encodes and decodes atomic values" do
    assert {:ok, <<0x16, 0x02, 0x00, 0x00>>} = Types.encode(:dint, 534)
    assert {:ok, 534} = Types.decode(:dint, <<0x16, 0x02, 0x00, 0x00>>)

    assert {:ok, <<0xFF>>} = Types.encode(:sint, -1)
    assert {:ok, -1} = Types.decode(:sint, <<0xFF>>)

    assert {:ok, bin} = Types.encode(:real, 1.5)
    assert {:ok, 1.5} = Types.decode(:real, bin)

    assert {:ok, <<1>>} = Types.encode(:bool, true)
    assert {:ok, false} = Types.decode(:bool, <<0>>)
  end

  test "decode rejects size mismatches without raising" do
    assert {:error, :bad_value} = Types.decode(:dint, <<1, 2>>)
    assert {:error, :bad_value} = Types.encode(:sint, 40_000)
  end

  test "decode_typed parses a Logix read reply payload" do
    assert {:ok, {:dint, 534}} = Types.decode_typed(<<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>)
    # two-element array of INT
    assert {:ok, {:int, [7, 8]}} = Types.decode_typed(<<0xC3, 0x00, 7, 0, 8, 0>>)
    # structure: 0x02A0 marker + template handle + raw data
    assert {:ok, {:struct, 0x0FAB, <<1, 2, 3>>}} =
             Types.decode_typed(<<0xA0, 0x02, 0xAB, 0x0F, 1, 2, 3>>)
  end

  test "decode_symbol_type: atomic DINT" do
    assert %{
             structure?: false,
             system?: false,
             dims: 0,
             atomic_type: :dint,
             template_instance: nil,
             bool_position: nil
           } =
             Types.decode_symbol_type(0x00C4)
  end

  test "decode_symbol_type: 1-dim array of REAL" do
    # bit 13 set = 1 dimension
    assert %{structure?: false, dims: 1, atomic_type: :real} =
             Types.decode_symbol_type(0x20CA)
  end

  test "decode_symbol_type: structure with template instance" do
    # bit 15 set, bits 11-0 = template instance 0x2E9
    assert %{structure?: true, template_instance: 0x2E9, atomic_type: nil} =
             Types.decode_symbol_type(0x82E9)
  end

  test "decode_symbol_type: system tag and BOOL bit position" do
    assert %{system?: true} = Types.decode_symbol_type(0x1000)
    assert %{atomic_type: :bool, bool_position: 3} = Types.decode_symbol_type(0x03C1)
  end
end
