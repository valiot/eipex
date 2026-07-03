defmodule Eipex.CIP.LogixTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.Logix

  test "read tag: TotalCount, 1 element (manual example)" do
    assert Logix.encode_read_tag(symbolic: "TotalCount") ==
             <<0x4C, 0x06, 0x91, 0x0A, "TotalCount", 0x01, 0x00>>
  end

  test "read tag fragmented appends a 4-byte offset" do
    assert Logix.encode_read_tag_fragmented([symbolic: "TotalCount"], 1, 490) ==
             <<0x52, 0x06, 0x91, 0x0A, "TotalCount", 0x01, 0x00, 490::32-little>>
  end

  test "write tag: CartonSize = 14 as DINT (manual example)" do
    assert Logix.encode_write_tag(
             [symbolic: "CartonSize"],
             <<0xC4, 0x00>>,
             1,
             <<0x0E, 0x00, 0x00, 0x00>>
           ) ==
             <<0x4D, 0x06, 0x91, 0x0A, "CartonSize", 0xC4, 0x00, 0x01, 0x00, 0x0E, 0x00, 0x00,
               0x00>>
  end

  test "read-modify-write: set bit 2, clear bit 5 of ControlWord (manual example)" do
    assert Logix.encode_rmw(
             [symbolic: "ControlWord"],
             <<0x04, 0x00, 0x00, 0x00>>,
             <<0xDF, 0xFF, 0xFF, 0xFF>>
           ) ==
             <<0x4E, 0x07, 0x91, 0x0B, "ControlWord", 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
               0xDF, 0xFF, 0xFF, 0xFF>>
  end

  test "rmw rejects invalid mask sizes" do
    assert_raise FunctionClauseError, fn ->
      Logix.encode_rmw([symbolic: "X"], <<1, 2, 3>>, <<1, 2, 3>>)
    end
  end

  test "multiple service packet builds the offset table" do
    # 8 bytes
    r1 = Logix.encode_read_tag(symbolic: "AB")
    # 10 bytes
    r2 = Logix.encode_read_tag(symbolic: "CDEF")
    msp = Logix.encode_multiple_service([r1, r2])

    # service 0x0A, path 20 02 24 01, count 2, offsets 6 and 6+8=14
    assert <<0x0A, 0x02, 0x20, 0x02, 0x24, 0x01, 2::16-little, 6::16-little, 14::16-little,
             rest::binary>> = msp

    assert rest == r1 <> r2
  end

  test "multiple service reply splits embedded replies" do
    rep1 = <<0xCC, 0x00, 0x00, 0x00, 0xC4, 0x00, 1, 0, 0, 0>>
    rep2 = <<0xCC, 0x00, 0x05, 0x00>>

    data =
      <<2::16-little, 6::16-little, 6 + byte_size(rep1)::16-little, rep1::binary, rep2::binary>>

    assert {:ok, [^rep1, ^rep2]} = Logix.decode_multiple_service_reply(data)
    assert {:error, :malformed_msp} = Logix.decode_multiple_service_reply(<<9::16-little>>)
  end

  test "symbol list request asks for attributes 1 and 2 from an instance" do
    assert Logix.encode_symbol_list(0) ==
             <<0x55, 0x03, 0x20, 0x6B, 0x25, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
               0x00>>
  end

  test "encode_symbol_list rejects instances beyond 16 bits" do
    assert_raise FunctionClauseError, fn -> Logix.encode_symbol_list(0x10000) end
  end

  test "symbol list reply parses instances, names and types" do
    data =
      <<0x10::32-little, 5::16-little, "MyTag", 0x00C4::16-little, 0x25::32-little, 3::16-little,
        "Str", 0x82E9::16-little>>

    assert {:ok,
            [
              %{
                instance: 0x10,
                name: "MyTag",
                raw_type: 0x00C4,
                symbol_type: %{atomic_type: :dint}
              },
              %{
                instance: 0x25,
                name: "Str",
                symbol_type: %{structure?: true, template_instance: 0x2E9}
              }
            ]} =
             Logix.decode_symbol_list(data)
  end

  test "template attribute request matches the manual example" do
    assert Logix.encode_template_attributes(0x02E9) ==
             <<0x03, 0x03, 0x20, 0x6C, 0x25, 0x00, 0xE9, 0x02, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00,
               0x02, 0x00, 0x01, 0x00>>
  end

  test "template attribute reply parses the four attributes" do
    # count 4, then per attribute: id, status 0, value
    data =
      <<4::16-little, 4::16-little, 0::16-little, 0x68::32-little, 5::16-little, 0::16-little,
        0x20::32-little, 2::16-little, 0::16-little, 3::16-little, 1::16-little, 0::16-little,
        0x0FAB::16-little>>

    assert {:ok, %{definition_size: 0x68, structure_size: 0x20, member_count: 3, handle: 0x0FAB}} =
             Logix.decode_template_attributes(data)
  end

  test "read template request carries offset and byte count" do
    assert Logix.encode_read_template(0x02E9, 0, 393) ==
             <<0x4C, 0x03, 0x20, 0x6C, 0x25, 0x00, 0xE9, 0x02, 0::32-little, 393::16-little>>
  end

  test "template definition parses members then names" do
    # 2 members (8 bytes each), then template name ';'-terminated info,
    # then member names, all null-terminated.
    members =
      <<0::16-little, 0x00C1::16-little, 0::32-little, 12::16-little, 0x00C3::16-little,
        4::32-little>>

    names = <<"MyUDT;n", 0, "pilot_on", 0, "hourlyCount", 0>>

    assert {:ok,
            %{
              name: "MyUDT",
              members: [
                %{name: "pilot_on", raw_type: 0x00C1, info: 0, offset: 0},
                %{name: "hourlyCount", raw_type: 0x00C3, info: 12, offset: 4}
              ]
            }} =
             Logix.decode_template_definition(members <> names, 2)
  end

  test "template attribute reply with unexpected attribute id returns error" do
    data = <<1::16-little, 9::16-little, 0::16-little, 0xAB, 0xCD>>
    assert {:error, :malformed_template} = Logix.decode_template_attributes(data)
  end

  test "write tag fragmented carries type, count, offset and data" do
    assert Logix.encode_write_tag_fragmented(
             [symbolic: "CartonSize"],
             <<0xC4, 0x00>>,
             1,
             8,
             <<0x0E, 0x00, 0x00, 0x00>>
           ) ==
             <<0x53, 0x06, 0x91, 0x0A, "CartonSize", 0xC4, 0x00, 0x01, 0x00, 8::32-little, 0x0E,
               0x00, 0x00, 0x00>>
  end
end
