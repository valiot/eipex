defmodule Eipex.Adapter.Object.AssemblyTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.{AssemblyStore, Config, MessageRouter}
  alias Eipex.CIP.MessageRouter, as: MR

  defmodule PickyHandler do
    use Eipex.Adapter.Handler
    # config assembly (151) only accepts values starting with 0xA5
    def after_assembly_write(151, <<0xA5, _::binary>>, _ctx), do: :ok
    def after_assembly_write(151, _data, _ctx), do: {:error, 0x09}
    def after_assembly_write(_instance, _data, _ctx), do: :ok

    def before_assembly_read(100, _ctx), do: {:ok, <<9, 9, 9, 9>>}
    def before_assembly_read(_instance, _ctx), do: :keep
  end

  defp config(handler \\ Eipex.Adapter.Handler.Default) do
    {:ok, store} =
      AssemblyStore.start_link(
        input: [instance: 100, size: 4],
        output: [instance: 150, size: 4],
        config: [instance: 151, size: 2]
      )

    %Config{
      identity: nil,
      handler: handler,
      store: store,
      objects: %{0x04 => Eipex.Adapter.Object.Assembly}
    }
  end

  defp roundtrip(config, service, path, data \\ <<>>) do
    request = MR.encode_request(service, path, data)
    {:ok, response} = config |> MessageRouter.dispatch(request) |> MR.decode_response()
    response
  end

  test "reads data and size attributes" do
    cfg = config()

    assert %{status_name: :success, data: <<0, 0, 0, 0>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 3)

    assert %{data: <<4::16-little>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 4)
  end

  test "writes the output assembly and reads it back" do
    cfg = config()

    assert %{status_name: :success} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2, 3, 4>>)

    assert %{data: <<1, 2, 3, 4>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 3)
  end

  test "input assemblies are not settable over the network" do
    assert %{status_name: :attribute_not_settable} =
             roundtrip(config(), 0x10, [class: 0x04, instance: 100, attribute: 3], <<1, 2, 3, 4>>)
  end

  test "size mismatches map to not-enough / too-much data" do
    cfg = config()

    assert %{status_name: :not_enough_data} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2>>)

    assert %{status_name: :too_much_data} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 150, attribute: 3], <<1, 2, 3, 4, 5>>)
  end

  test "handler can reject writes; store stays untouched" do
    cfg = config(PickyHandler)

    assert %{status_name: :invalid_attribute_value} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 151, attribute: 3], <<0xFF, 0x00>>)

    assert {:ok, <<0, 0>>} = AssemblyStore.read(cfg.store, 151)

    assert %{status_name: :success} =
             roundtrip(cfg, 0x10, [class: 0x04, instance: 151, attribute: 3], <<0xA5, 0x01>>)

    assert {:ok, <<0xA5, 0x01>>} = AssemblyStore.read(cfg.store, 151)
  end

  test "handler refreshes input assemblies before reads" do
    cfg = config(PickyHandler)

    assert %{status_name: :success, data: <<9, 9, 9, 9>>} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 100, attribute: 3)

    assert {:ok, <<9, 9, 9, 9>>} = AssemblyStore.read(cfg.store, 100)
  end

  test "unknown instances and attributes" do
    cfg = config()

    assert %{status_name: :path_destination_unknown} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 99, attribute: 3)

    assert %{status_name: :attribute_not_supported} =
             roundtrip(cfg, 0x0E, class: 0x04, instance: 150, attribute: 9)
  end
end
