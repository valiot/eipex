defmodule Eipex.Adapter.AssemblyStore do
  @moduledoc """
  Owns the assembly buffers: `instance => %{kind, size, data}`.
  Explicit messaging reads/writes go through here; the application refreshes
  produced data with `write/3` and consumes received data with `read/2`.
  """

  use GenServer

  @type kind :: :input | :output | :config

  def start_link(assemblies), do: GenServer.start_link(__MODULE__, assemblies)

  @spec read(GenServer.server(), non_neg_integer()) :: {:ok, binary()} | {:error, :no_assembly}
  def read(store, instance), do: GenServer.call(store, {:read, instance})

  @spec write(GenServer.server(), non_neg_integer(), binary()) ::
          :ok | {:error, :no_assembly | :size_mismatch}
  def write(store, instance, data), do: GenServer.call(store, {:write, instance, data})

  @spec info(GenServer.server(), non_neg_integer()) ::
          {:ok, %{kind: kind(), size: pos_integer()}} | {:error, :no_assembly}
  def info(store, instance), do: GenServer.call(store, {:info, instance})

  @impl true
  def init(assemblies) do
    buffers =
      for {kind, spec} <- assemblies, into: %{} do
        instance = Keyword.fetch!(spec, :instance)
        size = Keyword.fetch!(spec, :size)
        {instance, %{kind: kind, size: size, data: :binary.copy(<<0>>, size)}}
      end

    {:ok, buffers}
  end

  @impl true
  def handle_call({:read, instance}, _from, buffers) do
    case buffers do
      %{^instance => %{data: data}} -> {:reply, {:ok, data}, buffers}
      _ -> {:reply, {:error, :no_assembly}, buffers}
    end
  end

  def handle_call({:write, instance, data}, _from, buffers) do
    case buffers do
      %{^instance => %{size: size} = buffer} when byte_size(data) == size ->
        {:reply, :ok, %{buffers | instance => %{buffer | data: data}}}

      %{^instance => _} ->
        {:reply, {:error, :size_mismatch}, buffers}

      _ ->
        {:reply, {:error, :no_assembly}, buffers}
    end
  end

  def handle_call({:info, instance}, _from, buffers) do
    case buffers do
      %{^instance => %{kind: kind, size: size}} ->
        {:reply, {:ok, %{kind: kind, size: size}}, buffers}

      _ ->
        {:reply, {:error, :no_assembly}, buffers}
    end
  end
end
