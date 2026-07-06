defmodule Eipex.Adapter.ConnectedObjectsTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{Config, ConnectionTable, MessageRouter}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  defp config(max \\ 8) do
    {:ok, table} = ConnectionTable.start_link(max: max)

    %Config{
      identity: nil,
      handler: Eipex.Adapter.Handler.Default,
      connections: table,
      objects: %{0x06 => Eipex.Adapter.Object.ConnectionManager}
    }
  end

  defp forward_open(overrides \\ []) do
    base = %CM.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: 0x1122_3344,
      connection_serial: 1,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      timeout_multiplier: 1,
      o2t_rpi: 10_000_000,
      o2t_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :variable,
        size: 500
      },
      t2o_rpi: 10_000_000,
      t2o_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :variable,
        size: 500
      },
      transport: %{direction: :server, trigger: :application, class: 3},
      connection_path: Path.encode(class: 0x02, instance: 0x01)
    }

    struct!(base, overrides)
  end

  defp dispatch(config, request) do
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "forward open registers a class 3 connection and replies with assigned ids" do
    cfg = config()
    request = CM.encode_forward_open(forward_open(), :standard)

    response = dispatch(cfg, request)
    assert response.status_name == :success

    {:ok, reply} = CM.decode_forward_open_reply(response.data)
    assert reply.t2o_connection_id == 0x1122_3344
    assert reply.o2t_connection_id != 0
    assert reply.o2t_api == 10_000_000

    assert {:ok, %{t2o_connection_id: 0x1122_3344}} =
             ConnectionTable.lookup_o2t(cfg.connections, reply.o2t_connection_id)
  end

  test "large forward open works too" do
    cfg = config()

    fo =
      forward_open(
        o2t_params: %{
          owner: :exclusive,
          type: :point_to_point,
          priority: :low,
          size_type: :variable,
          size: 4002
        },
        t2o_params: %{
          owner: :exclusive,
          type: :point_to_point,
          priority: :low,
          size_type: :variable,
          size: 4002
        }
      )

    response = dispatch(cfg, CM.encode_forward_open(fo, :large))
    assert response.status_name == :success
  end

  test "transport classes other than 1 and 3 answer 0x0103" do
    cfg = config()

    fo = forward_open(transport: %{direction: :server, trigger: :cyclic, class: 5})
    response = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    assert response.status_name == :connection_failure
    assert response.extended == [0x0103]
  end

  test "connection paths not addressing the message router answer 0x0315" do
    cfg = config()

    fo = forward_open(connection_path: Path.encode(class: 0x04, instance: 100))
    response = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    assert response.extended == [0x0315]
  end

  test "a leading port segment is accepted (routed forward open)" do
    cfg = config()

    fo =
      forward_open(
        connection_path: Path.encode([{:port, 1, 0}, {:class, 0x02}, {:instance, 0x01}])
      )

    response = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    assert response.status_name == :success
  end

  test "duplicate triads and capacity are rejected" do
    cfg = config(1)
    request = CM.encode_forward_open(forward_open(), :standard)

    assert %{status_name: :success} = dispatch(cfg, request)
    assert %{extended: [0x0100]} = dispatch(cfg, request)

    other = CM.encode_forward_open(forward_open(connection_serial: 2), :standard)
    assert %{extended: [0x0113]} = dispatch(cfg, other)
  end

  test "forward close unregisters; unknown triads answer 0x0107" do
    cfg = config()
    fo = forward_open()

    %{status_name: :success} = dispatch(cfg, CM.encode_forward_open(fo, :standard))

    triad = %{connection_serial: 1, originator_vendor_id: 0x004D, originator_serial: 0xDEAD_0001}

    close = CM.encode_forward_close(triad, fo.connection_path, [])
    response = dispatch(cfg, close)
    assert response.status_name == :success

    assert {:ok, %{connection_serial: 1}} = CM.decode_forward_close_reply(response.data)
    assert %{extended: [0x0107]} = dispatch(cfg, close)
  end

  test "malformed forward open payloads answer 0x13" do
    cfg = config()
    request = MR.encode_request(0x54, [class: 0x06, instance: 1], <<1, 2, 3>>)
    assert %{status_name: :not_enough_data} = dispatch(cfg, request)
  end
end
