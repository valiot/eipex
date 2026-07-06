defmodule Eipex.Adapter.MessageRouterTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{Config, MessageRouter}
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.Identity

  defmodule RejectingHandler do
    use Eipex.Adapter.Handler
    def reset(1), do: {:error, 0x0C}
    def reset(_), do: :ok
  end

  defmodule CrashingObject do
    @behaviour Eipex.Adapter.Object
    def handle_service(_, _, _, _, _), do: raise("boom")
  end

  defp config(overrides \\ []) do
    identity = %Identity{
      vendor_id: 0x4D,
      device_type: 0x0C,
      product_code: 0x77,
      revision: {1, 2},
      serial_number: 0x99,
      product_name: "Eipex Adapter",
      status: 0,
      state: 3
    }

    struct!(
      %Config{
        identity: identity,
        objects: %{
          0x01 => Eipex.Adapter.Object.Identity,
          0x02 => Eipex.Adapter.Object.MessageRouterObject,
          0x64 => CrashingObject
        },
        handler: Eipex.Adapter.Handler.Default
      },
      overrides
    )
  end

  defp roundtrip(config, service, path, data \\ <<>>) do
    request = MR.encode_request(service, path, data)
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "get_attribute_single reads identity attributes" do
    assert %{status_name: :success, data: <<0x4D, 0x00>>} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 1)

    assert %{data: <<1, 2>>} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 4)

    assert %{data: <<13, "Eipex Adapter">>} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 7)
  end

  test "get_attributes_all concatenates attributes 1..7" do
    assert %{status_name: :success, data: data} =
             roundtrip(config(), 0x01, class: 0x01, instance: 1)

    assert data ==
             <<0x4D::16-little, 0x0C::16-little, 0x77::16-little, 1, 2, 0::16-little,
               0x99::32-little, 13, "Eipex Adapter">>
  end

  test "reset delegates to the handler" do
    assert %{status_name: :success} = roundtrip(config(), 0x05, class: 0x01, instance: 1)

    cfg = config(handler: RejectingHandler)
    assert %{status: 0x0C} = roundtrip(cfg, 0x05, [class: 0x01, instance: 1], <<1>>)
  end

  test "CIP error statuses for bad addressing" do
    assert %{status_name: :attribute_not_supported} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 1, attribute: 99)

    assert %{status_name: :path_destination_unknown} =
             roundtrip(config(), 0x0E, class: 0x01, instance: 9, attribute: 1)

    assert %{status_name: :path_destination_unknown} =
             roundtrip(config(), 0x0E, class: 0x77, instance: 1, attribute: 1)

    assert %{status_name: :service_not_supported} =
             roundtrip(config(), 0x32, class: 0x01, instance: 1)

    assert %{status_name: :service_not_supported} =
             roundtrip(config(), 0x0A, class: 0x02, instance: 1)
  end

  test "symbolic paths are unknown destinations on an adapter" do
    assert %{status_name: :path_destination_unknown} =
             roundtrip(config(), 0x4C, [symbolic: "MyTag"], <<1::16-little>>)
  end

  test "malformed requests and paths degrade to error responses, never raise" do
    {:ok, resp} = config() |> MessageRouter.dispatch(<<0x0E, 0x09, 0x91>>) |> MR.decode_response()
    assert resp.status_name == :not_enough_data

    bad_path = <<0x0E, 0x01, 0xFF, 0x00>>
    {:ok, resp2} = config() |> MessageRouter.dispatch(bad_path) |> MR.decode_response()
    assert resp2.status_name == :path_segment_error
  end

  test "a crashing object maps to vendor-specific error, not a crash" do
    import ExUnit.CaptureLog

    log =
      capture_log(fn ->
        assert %{status_name: :vendor_specific_error} =
                 roundtrip(config(), 0x0E, class: 0x64, instance: 1, attribute: 1)
      end)

    assert log =~ "boom"
  end

  defmodule ExtraCpfObject do
    @behaviour Eipex.Adapter.Object

    def handle_service(0x0E, 1, _path, _data, ctx) do
      # echoes how many CPF items the session handed us, and returns a sockaddr
      count = length(Map.get(ctx, :cpf_items, []))

      {:reply, <<count>>, [{:sockaddr_o2t, %{ip: {127, 0, 0, 1}, port: 4321}}]}
    end
  end

  test "dispatch/3 threads cpf items in and extra cpf items out" do
    cfg = config()
    cfg = %{cfg | objects: Map.put(cfg.objects, 0x65, ExtraCpfObject)}

    request = MR.encode_request(0x0E, class: 0x65, instance: 1)

    {response, extra} =
      MessageRouter.dispatch(cfg, request, %{
        cpf_items: [:null_address, {:unconnected_data, <<>>}]
      })

    assert {:ok, %{status_name: :success, data: <<2>>}} = MR.decode_response(response)
    assert extra == [{:sockaddr_o2t, %{ip: {127, 0, 0, 1}, port: 4321}}]
  end

  test "dispatch/2 keeps the old binary contract" do
    cfg = config()
    cfg = %{cfg | objects: Map.put(cfg.objects, 0x65, ExtraCpfObject)}

    request = MR.encode_request(0x0E, class: 0x65, instance: 1)
    response = MessageRouter.dispatch(cfg, request)

    assert is_binary(response)
    assert {:ok, %{data: <<0>>}} = MR.decode_response(response)
  end
end
