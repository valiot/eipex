defmodule Eipex.Adapter.Object.Assembly do
  @moduledoc """
  Assembly object (class 0x04). Attribute 3 is the data buffer, attribute 4
  its size. `:input` (produced) assemblies refresh through the application
  handler before reads and reject network writes; `:output`/`:config`
  writes validate size, then the handler, then land in the store.
  """

  @behaviour Eipex.Adapter.Object

  alias Eipex.Adapter.AssemblyStore

  @get_attribute_single 0x0E
  @set_attribute_single 0x10

  @impl true
  def handle_service(@get_attribute_single, instance, [{:attribute, 3}], <<>>, ctx) do
    case AssemblyStore.info(ctx.store, instance) do
      {:ok, %{kind: :input}} -> {:reply, refreshed_read(instance, ctx)}
      {:ok, _} -> read(instance, ctx)
      {:error, :no_assembly} -> {:error, 0x05, []}
    end
  end

  def handle_service(@get_attribute_single, instance, [{:attribute, 4}], <<>>, ctx) do
    case AssemblyStore.info(ctx.store, instance) do
      {:ok, %{size: size}} -> {:reply, <<size::16-little>>}
      {:error, :no_assembly} -> {:error, 0x05, []}
    end
  end

  def handle_service(@get_attribute_single, instance, [{:attribute, _}], <<>>, ctx) do
    with {:ok, _} <- AssemblyStore.info(ctx.store, instance) do
      {:error, 0x14, []}
    else
      _ -> {:error, 0x05, []}
    end
  end

  def handle_service(@set_attribute_single, instance, [{:attribute, 3}], data, ctx) do
    case AssemblyStore.info(ctx.store, instance) do
      {:ok, %{kind: :input}} ->
        {:error, 0x0E, []}

      {:ok, %{size: size}} when byte_size(data) < size ->
        {:error, 0x13, []}

      {:ok, %{size: size}} when byte_size(data) > size ->
        {:error, 0x15, []}

      {:ok, _} ->
        case ctx.handler.after_assembly_write(instance, data, ctx) do
          :ok ->
            :ok = AssemblyStore.write(ctx.store, instance, data)
            {:reply, <<>>}

          {:error, status} ->
            {:error, status, []}
        end

      {:error, :no_assembly} ->
        {:error, 0x05, []}
    end
  end

  def handle_service(@set_attribute_single, instance, [{:attribute, _}], _data, ctx) do
    with {:ok, _} <- AssemblyStore.info(ctx.store, instance) do
      {:error, 0x14, []}
    else
      _ -> {:error, 0x05, []}
    end
  end

  def handle_service(_service, _instance, _path, _data, _ctx), do: {:error, 0x08, []}

  defp read(instance, ctx) do
    {:ok, data} = AssemblyStore.read(ctx.store, instance)
    {:reply, data}
  end

  defp refreshed_read(instance, ctx) do
    case ctx.handler.before_assembly_read(instance, ctx) do
      {:ok, fresh} ->
        case AssemblyStore.write(ctx.store, instance, fresh) do
          :ok ->
            fresh

          {:error, _} ->
            {:ok, stored} = AssemblyStore.read(ctx.store, instance)
            stored
        end

      :keep ->
        {:ok, stored} = AssemblyStore.read(ctx.store, instance)
        stored
    end
  end
end
