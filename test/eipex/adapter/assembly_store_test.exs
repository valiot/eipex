defmodule Eipex.Adapter.AssemblyStoreTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.AssemblyStore

  defp start_store do
    {:ok, store} =
      AssemblyStore.start_link(
        input: [instance: 100, size: 4],
        output: [instance: 150, size: 4],
        config: [instance: 151, size: 2]
      )

    store
  end

  test "buffers start zero-filled with the declared size" do
    store = start_store()
    assert {:ok, <<0, 0, 0, 0>>} = AssemblyStore.read(store, 100)
    assert {:ok, %{kind: :config, size: 2}} = AssemblyStore.info(store, 151)
  end

  test "write requires the exact declared size" do
    store = start_store()
    assert :ok = AssemblyStore.write(store, 150, <<1, 2, 3, 4>>)
    assert {:ok, <<1, 2, 3, 4>>} = AssemblyStore.read(store, 150)
    assert {:error, :size_mismatch} = AssemblyStore.write(store, 150, <<1, 2>>)
  end

  test "unknown instances error" do
    store = start_store()
    assert {:error, :no_assembly} = AssemblyStore.read(store, 99)
    assert {:error, :no_assembly} = AssemblyStore.write(store, 99, <<1>>)
    assert {:error, :no_assembly} = AssemblyStore.info(store, 99)
  end
end
