defmodule Eipex.CIP.MessageRouterTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.MessageRouter, as: MR

  # 1756-PM020: Read Tag "TotalCount", 1 element
  @read_request <<0x4C, 0x06, 0x91, 0x0A, "TotalCount", 0x01, 0x00>>
  # Reply: service|0x80, reserved, status 0, ext size 0, DINT type + value 534
  @read_reply <<0xCC, 0x00, 0x00, 0x00, 0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>

  test "encodes a request with a segment list path" do
    assert MR.encode_request(0x4C, [symbolic: "TotalCount"], <<1::16-little>>) ==
             @read_request
  end

  test "encodes a request with a pre-encoded binary path" do
    path = Eipex.CIP.Path.encode(symbolic: "TotalCount")
    assert MR.encode_request(0x4C, path, <<1::16-little>>) == @read_request
  end

  test "decodes a request (adapter side)" do
    assert {:ok, %{service: 0x4C, path: path, data: <<1, 0>>}} =
             MR.decode_request(@read_request)

    assert {:ok, [symbolic: "TotalCount"]} = Eipex.CIP.Path.decode(path)
  end

  test "decodes a success response" do
    assert {:ok,
            %{
              service: 0x4C,
              status: 0x00,
              status_name: :success,
              extended: [],
              data: <<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>
            }} =
             MR.decode_response(@read_reply)
  end

  test "encodes a success response" do
    assert MR.encode_response(0x4C, 0x00, data: <<0xC4, 0x00, 0x16, 0x02, 0x00, 0x00>>) ==
             @read_reply
  end

  test "encodes and decodes an error response with extended status" do
    bin = MR.encode_response(0x54, 0x01, extended: [0x0100])

    assert bin == <<0xD4, 0x00, 0x01, 0x01, 0x00, 0x01>>

    assert {:ok,
            %{status: 0x01, status_name: :connection_failure, extended: [0x0100], data: <<>>}} =
             MR.decode_response(bin)
  end

  test "status_name covers the CIP general status table" do
    assert MR.status_name(0x00) == :success
    assert MR.status_name(0x04) == :path_segment_error
    assert MR.status_name(0x05) == :path_destination_unknown
    assert MR.status_name(0x06) == :partial_transfer
    assert MR.status_name(0x08) == :service_not_supported
    assert MR.status_name(0x13) == :not_enough_data
    assert MR.status_name(0x14) == :attribute_not_supported
    assert MR.status_name(0x1E) == :embedded_service_error
    assert MR.status_name(0x26) == :path_size_invalid
    assert MR.status_name(0xF9) == :unknown
  end

  test "malformed inputs return errors, never raise" do
    assert {:error, :malformed_request} = MR.decode_request(<<0x4C, 0x09, 0x91>>)
    assert {:error, :malformed_response} = MR.decode_response(<<0xCC, 0x00, 0x00>>)
  end
end
