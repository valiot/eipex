defmodule Eipex.CIP.ConnectionManagerTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.ConnectionManager.{ForwardOpen, ForwardOpenReply}
  alias Eipex.CIP.Path

  defp sample_fo do
    %ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 5,
      o2t_connection_id: 0,
      t2o_connection_id: 0x1122_3344,
      connection_serial: 0xBEEF,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      timeout_multiplier: 1,
      o2t_rpi: 10_000,
      o2t_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :variable,
        size: 500
      },
      t2o_rpi: 10_000,
      t2o_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :variable,
        size: 500
      },
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(class: 0x02, instance: 1)
    }
  end

  test "network params bit layout, 16-bit (standard FO)" do
    params = %{
      owner: :exclusive,
      type: :point_to_point,
      priority: :low,
      size_type: :variable,
      size: 500
    }

    # p2p = 2<<13 (0x4000), variable = 1<<9 (0x0200), size 500 = 0x1F4 → 0x43F4
    assert CM.encode_params(:standard, params) == <<0xF4, 0x43>>
    assert CM.decode_params(:standard, <<0xF4, 0x43>>) == params
  end

  test "network params bit layout, 32-bit (large FO)" do
    params = %{
      owner: :exclusive,
      type: :point_to_point,
      priority: :low,
      size_type: :variable,
      size: 4002
    }

    # p2p = 2<<29, variable = 1<<25, size 4002 = 0x0FA2 → 0x42000FA2
    assert CM.encode_params(:large, params) == <<0xA2, 0x0F, 0x00, 0x42>>
    assert CM.decode_params(:large, <<0xA2, 0x0F, 0x00, 0x42>>) == params
  end

  test "transport class/trigger byte" do
    assert CM.encode_transport(%{direction: :server, trigger: :cyclic, class: 1}) == <<0x81>>
    assert CM.encode_transport(%{direction: :client, trigger: :application, class: 3}) == <<0x23>>
    assert CM.decode_transport(<<0x81>>) == %{direction: :server, trigger: :cyclic, class: 1}
  end

  test "forward open request round-trips (standard and large)" do
    fo = sample_fo()

    for variant <- [:standard, :large] do
      request = CM.encode_forward_open(fo, variant)
      service = if variant == :standard, do: 0x54, else: 0x5B

      assert {:ok, %{service: ^service, data: data}} =
               Eipex.CIP.MessageRouter.decode_request(request)

      assert {:ok, ^fo} = CM.decode_forward_open(service, data)
    end
  end

  test "forward open request targets the connection manager object" do
    assert <<0x54, 0x02, 0x20, 0x06, 0x24, 0x01, _::binary>> =
             CM.encode_forward_open(sample_fo(), :standard)
  end

  test "forward open reply round-trips" do
    reply = %ForwardOpenReply{
      o2t_connection_id: 0xAAAA_0001,
      t2o_connection_id: 0x1122_3344,
      connection_serial: 0xBEEF,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      o2t_api: 10_000,
      t2o_api: 10_000,
      application_reply: <<>>
    }

    assert {:ok, ^reply} =
             reply |> CM.encode_forward_open_reply() |> CM.decode_forward_open_reply()
  end

  test "forward close carries the triad and path" do
    triad = %{
      connection_serial: 0xBEEF,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001
    }

    path = Path.encode(class: 0x02, instance: 1)
    request = CM.encode_forward_close(triad, path, [])

    assert {:ok, %{service: 0x4E, data: data}} =
             Eipex.CIP.MessageRouter.decode_request(request)

    assert {:ok,
            %{
              connection_serial: 0xBEEF,
              originator_vendor_id: 0x004D,
              originator_serial: 0xDEAD_0001,
              connection_path: ^path
            }} =
             CM.decode_forward_close(data)
  end

  test "unconnected send pads odd embedded messages (trap #2)" do
    # 11-byte embedded request (odd): 2 header + 6 path + 3 data
    embedded = Eipex.CIP.MessageRouter.encode_request(0x4C, [symbolic: "abc"], <<1, 2, 3>>)
    assert rem(byte_size(embedded), 2) == 1

    request = CM.encode_unconnected_send(embedded, [{:port, 1, 0}], [])
    {:ok, %{service: 0x52, data: data}} = Eipex.CIP.MessageRouter.decode_request(request)

    size = byte_size(embedded)

    # after the embedded message: pad 0x00, route words 1, reserved 0x00,
    # route path <<0x01, 0x00>> (backplane slot 0)
    assert <<_ptt, _ticks, ^size::16-little, ^embedded::binary-size(size), 0x00, 0x01, 0x00, 0x01,
             0x00>> = data
  end

  test "extended status names and timeout factor" do
    assert CM.ext_status_name(0x0100) == :connection_in_use
    assert CM.ext_status_name(0x0106) == :ownership_conflict
    assert CM.ext_status_name(0x0113) == :out_of_connections
    assert CM.ext_status_name(0x9999) == :unknown
    assert CM.timeout_factor(0) == 4
    assert CM.timeout_factor(2) == 16
  end

  test "encode_params rejects sizes beyond the variant's field width" do
    params = %{
      owner: :exclusive,
      type: :point_to_point,
      priority: :low,
      size_type: :variable,
      size: 1000
    }

    # 1000 > 0x1FF: must raise, not silently wrap to 488
    assert_raise FunctionClauseError, fn -> CM.encode_params(:standard, params) end

    # but fits in the large (16-bit) field
    assert CM.encode_params(:large, %{params | size: 1000}) |> byte_size() == 4

    assert_raise FunctionClauseError, fn ->
      CM.encode_params(:large, %{params | size: 0x10000})
    end
  end

  test "unconnected send round-trips through decode (odd and even embedded)" do
    for data <- [<<1, 2, 3>>, <<1, 2>>] do
      embedded = Eipex.CIP.MessageRouter.encode_request(0x4C, [symbolic: "abc"], data)
      request = CM.encode_unconnected_send(embedded, [{:port, 1, 0}], timeout_ticks: 7)
      {:ok, %{service: 0x52, data: payload}} = Eipex.CIP.MessageRouter.decode_request(request)

      assert {:ok,
              %{
                embedded: ^embedded,
                route: <<0x01, 0x00>>,
                priority_time_tick: 0x0A,
                timeout_ticks: 7
              }} =
               CM.decode_unconnected_send(payload)
    end
  end

  test "decode_unconnected_send rejects truncated payloads" do
    assert {:error, :malformed_unconnected_send} =
             CM.decode_unconnected_send(<<1, 2, 9::16-little, 1>>)

    assert {:error, :malformed_unconnected_send} = CM.decode_unconnected_send(<<1>>)
  end

  test "decode_unconnected_send rejects truncated route after a complete embedded message" do
    # embedded parses (2 bytes, even), but route_words claims 2 words with only 1 byte present
    data = <<0x0A, 5, 2::16-little, 0xAA, 0xBB, 2, 0, 0x01>>
    assert {:error, :malformed_unconnected_send} = CM.decode_unconnected_send(data)
  end

  test "forward close reply round-trips" do
    triad = %{
      connection_serial: 0xBEEF,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001
    }

    reply = CM.encode_forward_close_reply(triad)

    assert reply ==
             <<0xBEEF::16-little, 0x004D::16-little, 0xDEAD_0001::32-little, 0, 0>>

    assert {:ok,
            %{
              connection_serial: 0xBEEF,
              originator_vendor_id: 0x004D,
              originator_serial: 0xDEAD_0001
            }} = CM.decode_forward_close_reply(reply)

    assert {:error, :malformed_reply} = CM.decode_forward_close_reply(<<1, 2, 3>>)
  end

  test "forward open error reply decodes the triad" do
    body = <<0xBEEF::16-little, 0x004D::16-little, 0xDEAD_0001::32-little, 1, 0>>

    assert {:ok,
            %{
              connection_serial: 0xBEEF,
              originator_vendor_id: 0x004D,
              originator_serial: 0xDEAD_0001,
              remaining_path_size: 1
            }} =
             CM.decode_forward_open_error(body)

    assert {:error, :malformed_reply} = CM.decode_forward_open_error(<<1, 2>>)
  end

  test "new extended status names" do
    assert CM.ext_status_name(0x0103) == :transport_trigger_not_supported
    assert CM.ext_status_name(0x0107) == :target_connection_not_found
  end
end
