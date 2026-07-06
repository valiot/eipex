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

  @spec port(GenServer.server()) :: {:ok, :inet.port_number()}
  def port(server), do: GenServer.call(server, :port)

  @spec discovery_port(GenServer.server()) ::
          {:ok, :inet.port_number()} | {:error, :not_running}
  def discovery_port(server), do: GenServer.call(server, :discovery_port)

  @spec io_udp_port(GenServer.server()) :: {:ok, :inet.port_number()} | {:error, term()}
  def io_udp_port(server), do: GenServer.call(server, :io_udp_port)

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
    listen_opts = [
      :binary,
      packet: :raw,
      active: false,
      reuseaddr: true,
      ip: Keyword.get(opts, :ip, {0, 0, 0, 0})
    ]

    network = Map.new(Keyword.get(opts, :network, []))

    with {:ok, listen} <- :gen_tcp.listen(Keyword.get(opts, :port, 44_818), listen_opts),
         {:ok, resolved_port} <- :inet.port(listen),
         {:ok, identity} <- build_identity(Keyword.get(opts, :identity), network, resolved_port),
         {:ok, store} <- AssemblyStore.start_link(Keyword.get(opts, :assemblies, [])),
         {:ok, connections} <-
           Eipex.Adapter.ConnectionTable.start_link(max: Keyword.get(opts, :max_connections, 8)),
         {:ok, io_udp} <-
           Eipex.Adapter.UDP.start_link(%{
             port: Keyword.get(opts, :io_udp_port, 2222),
             connections: connections
           }),
         {:ok, io_sup} <- DynamicSupervisor.start_link(strategy: :one_for_one),
         {:ok, sessions_sup} <- DynamicSupervisor.start_link(strategy: :one_for_one) do
      io_opts = Keyword.get(opts, :io, [])

      io = %{
        udp: io_udp,
        sup: io_sup,
        o2t_run_idle: Keyword.get(io_opts, :o2t_run_idle, true),
        t2o_run_idle: Keyword.get(io_opts, :t2o_run_idle, false)
      }

      config = %Config{
        identity: identity,
        objects: Map.merge(@default_objects, Map.new(Keyword.get(opts, :objects, []))),
        handler: Keyword.get(opts, :handler, Eipex.Adapter.Handler.Default),
        store: store,
        inactivity_timeout: Keyword.get(opts, :inactivity_timeout, 120_000),
        network: network,
        connections: connections,
        io: io
      }

      {:ok, listener} =
        Eipex.Adapter.Listener.start_link(%{
          listen: listen,
          sessions_sup: sessions_sup,
          config: config
        })

      discovery =
        case Keyword.get(opts, :discovery, false) do
          false ->
            nil

          disc_opts ->
            {:ok, pid} =
              Eipex.Adapter.Discovery.start_link(%{
                port: Keyword.get(disc_opts, :port, 44_818),
                delay: Keyword.get(disc_opts, :delay, {0, 500}),
                config: config
              })

            pid
        end

      {:ok,
       %{
         config: config,
         sessions_sup: sessions_sup,
         listener: listener,
         discovery: discovery,
         opts: opts,
         port: resolved_port
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state) do
    {:reply, {:ok, state.port}, state}
  end

  def handle_call(:discovery_port, _from, state) do
    case state.discovery do
      nil -> {:reply, {:error, :not_running}, state}
      pid -> {:reply, Eipex.Adapter.Discovery.port(pid), state}
    end
  end

  def handle_call(:io_udp_port, _from, state) do
    {:reply, Eipex.Adapter.UDP.port(state.config.io.udp), state}
  end

  def handle_call({:read_assembly, instance}, _from, state) do
    {:reply, AssemblyStore.read(state.config.store, instance), state}
  end

  def handle_call({:write_assembly, instance, data}, _from, state) do
    {:reply, AssemblyStore.write(state.config.store, instance, data), state}
  end

  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  # -- Option handling -----------------------------------------------------------

  defp build_identity(nil, _network, _port), do: {:error, :missing_identity}

  defp build_identity(opts, network, port) do
    case Enum.find([:vendor_id, :product_code, :product_name], &(not Keyword.has_key?(opts, &1))) do
      nil ->
        {:ok,
         %Identity{
           ip: Map.get(network, :ip, {0, 0, 0, 0}),
           port: port,
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
