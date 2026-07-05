defmodule Eipex.Adapter do
  @moduledoc """
  EtherNet/IP adapter (target) for explicit messaging.

  One process tree per adapter: this GenServer owns (links) the assembly
  store, the session-handler supervisor and the TCP listener. If any of
  them dies the whole adapter dies and the owning application's supervisor
  decides — mirroring the scanner's no-magic-recovery contract.
  """

  use GenServer

  alias Eipex.Adapter.{AssemblyStore, Config}
  alias Eipex.Identity

  @default_objects %{
    0x01 => Eipex.Adapter.Object.Identity,
    0x02 => Eipex.Adapter.Object.MessageRouterObject,
    0x04 => Eipex.Adapter.Object.Assembly,
    0x06 => Eipex.Adapter.Object.ConnectionManager,
    0xF5 => Eipex.Adapter.Object.TcpIpInterface,
    0xF6 => Eipex.Adapter.Object.EthernetLink
  }

  # -- Public API --------------------------------------------------------------

  def start_link(opts) do
    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, :not_listening}
  def port(server), do: GenServer.call(server, :port)

  @spec read_assembly(GenServer.server(), non_neg_integer()) ::
          {:ok, binary()} | {:error, term()}
  def read_assembly(server, instance), do: GenServer.call(server, {:read_assembly, instance})

  @spec write_assembly(GenServer.server(), non_neg_integer(), binary()) ::
          :ok | {:error, term()}
  def write_assembly(server, instance, data),
    do: GenServer.call(server, {:write_assembly, instance, data})

  @doc false
  def config(server), do: GenServer.call(server, :config)

  # -- GenServer ---------------------------------------------------------------

  @impl true
  def init(opts) do
    with {:ok, identity} <- build_identity(Keyword.get(opts, :identity)),
         {:ok, store} <- AssemblyStore.start_link(Keyword.get(opts, :assemblies, [])),
         {:ok, sessions_sup} <- DynamicSupervisor.start_link(strategy: :one_for_one) do
      config = %Config{
        identity: identity,
        objects: Map.merge(@default_objects, Map.new(Keyword.get(opts, :objects, []))),
        handler: Keyword.get(opts, :handler, Eipex.Adapter.Handler.Default),
        store: store,
        inactivity_timeout: Keyword.get(opts, :inactivity_timeout, 120_000),
        network: Map.new(Keyword.get(opts, :network, []))
      }

      {:ok, listener} =
        Eipex.Adapter.Listener.start_link(%{
          port: Keyword.get(opts, :port, 44_818),
          ip: Keyword.get(opts, :ip, {0, 0, 0, 0}),
          sessions_sup: sessions_sup,
          config: config
        })

      {:ok, %{config: config, sessions_sup: sessions_sup, listener: listener, opts: opts}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state) do
    {:reply, Eipex.Adapter.Listener.port(state.listener), state}
  end

  def handle_call({:read_assembly, instance}, _from, state) do
    {:reply, AssemblyStore.read(state.config.store, instance), state}
  end

  def handle_call({:write_assembly, instance, data}, _from, state) do
    {:reply, AssemblyStore.write(state.config.store, instance, data), state}
  end

  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  # -- Option handling -----------------------------------------------------------

  defp build_identity(nil), do: {:error, :missing_identity}

  defp build_identity(opts) do
    case Enum.find([:vendor_id, :product_code, :product_name], &(not Keyword.has_key?(opts, &1))) do
      nil ->
        {:ok,
         %Identity{
           vendor_id: Keyword.fetch!(opts, :vendor_id),
           device_type: Keyword.get(opts, :device_type, 0x0C),
           product_code: Keyword.fetch!(opts, :product_code),
           revision: Keyword.get(opts, :revision, {1, 0}),
           serial_number: Keyword.get(opts, :serial_number, 0),
           product_name: Keyword.fetch!(opts, :product_name),
           state: 3
         }}

      missing ->
        {:error, {:missing_identity_option, missing}}
    end
  end
end
