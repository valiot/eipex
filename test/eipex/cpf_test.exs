defmodule Eipex.CPFTest do
  use ExUnit.Case, async: true

  alias Eipex.{CPF, Identity}

  test "encodes UCMM pair: null address + unconnected data" do
    assert CPF.encode([:null_address, {:unconnected_data, <<0xAA, 0xBB>>}]) ==
             <<2::16-little, 0x0000::16-little, 0::16-little, 0x00B2::16-little, 2::16-little,
               0xAA, 0xBB>>
  end

  test "encodes connected pair with address item" do
    assert CPF.encode([{:connected_address, 0x0102_0304}, {:connected_data, <<1>>}]) ==
             <<2::16-little, 0x00A1::16-little, 4::16-little, 0x0102_0304::32-little,
               0x00B1::16-little, 1::16-little, 1>>
  end

  test "encodes sequenced address item for class 1 I/O" do
    assert CPF.encode([{:sequenced_address, 0xCAFE, 7}, {:connected_data, <<9>>}]) ==
             <<2::16-little, 0x8002::16-little, 8::16-little, 0xCAFE::32-little, 7::32-little,
               0x00B1::16-little, 1::16-little, 9>>
  end

  test "sockaddr items are big-endian inside a little-endian frame" do
    item = {:sockaddr_t2o, %{ip: {192, 168, 1, 10}, port: 2222}}

    assert CPF.encode([item]) ==
             <<1::16-little, 0x8001::16-little, 16::16-little, 2::16-big, 2222::16-big, 192, 168,
               1, 10, 0::64>>

    assert {:ok, [^item]} = CPF.decode(CPF.encode([item]))
  end

  test "round-trips every item type" do
    items = [
      :null_address,
      {:connected_address, 1},
      {:sequenced_address, 2, 3},
      {:unconnected_data, <<1, 2>>},
      {:connected_data, <<3>>},
      {:sockaddr_o2t, %{ip: {10, 0, 0, 1}, port: 2222}}
    ]

    assert {:ok, ^items} = items |> CPF.encode() |> CPF.decode()
  end

  test "decode tolerates unknown item types" do
    bin = <<1::16-little, 0x00FF::16-little, 2::16-little, 7, 8>>
    assert {:ok, [{:unknown, 0x00FF, <<7, 8>>}]} = CPF.decode(bin)
  end

  test "decode rejects truncated items without raising" do
    assert {:error, :malformed_cpf} =
             CPF.decode(<<2::16-little, 0x00B2::16-little, 9::16-little, 1>>)
  end

  test "decode rejects known item types with wrong-length payloads" do
    # connected address (0x00A1) must be exactly 4 bytes; 3 is malformed
    bin = <<1::16-little, 0x00A1::16-little, 3::16-little, 1, 2, 3>>
    assert {:error, :malformed_cpf} = CPF.decode(bin)
  end

  test "decode rejects trailing bytes beyond the declared item count" do
    bin = <<1::16-little, 0x0000::16-little, 0::16-little, 0xFF>>
    assert {:error, :malformed_cpf} = CPF.decode(bin)
  end

  # ListIdentity response item body (research §1): version 1, sockaddr (BE),
  # vendor 0x004D, type 0x0C, product 0x77, rev 1.2, status 0, serial 0x99,
  # name "Eipex", state 3.
  @identity_body <<1::16-little, 2::16-big, 44818::16-big, 10, 0, 0, 5, 0::64, 0x4D::16-little,
                   0x0C::16-little, 0x77::16-little, 1, 2, 0::16-little, 0x99::32-little, 5,
                   "Eipex", 3>>

  test "decodes a ListIdentity identity item via CPF" do
    cpf =
      <<1::16-little, 0x000C::16-little, byte_size(@identity_body)::16-little,
        @identity_body::binary>>

    assert {:ok,
            [
              {:identity,
               %Identity{
                 vendor_id: 0x4D,
                 device_type: 0x0C,
                 product_code: 0x77,
                 revision: {1, 2},
                 serial_number: 0x99,
                 product_name: "Eipex",
                 ip: {10, 0, 0, 5},
                 port: 44818,
                 state: 3
               }}
            ]} =
             CPF.decode(cpf)
  end

  test "identity item round-trips" do
    {:ok, [{:identity, id}]} =
      CPF.decode(
        <<1::16-little, 0x000C::16-little, byte_size(@identity_body)::16-little,
          @identity_body::binary>>
      )

    assert Identity.encode_item(id) == @identity_body
  end
end
