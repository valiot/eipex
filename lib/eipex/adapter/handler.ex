defmodule Eipex.Adapter.Handler do
  @moduledoc """
  Application-side callbacks for the adapter. `use Eipex.Adapter.Handler`
  provides permissive defaults; override what you need. Returning
  `{:error, cip_status}` from a callback surfaces that status to the
  requesting scanner.
  """

  @callback after_assembly_write(instance :: non_neg_integer(), data :: binary(), ctx :: map()) ::
              :ok | {:error, byte()}
  @callback before_assembly_read(instance :: non_neg_integer(), ctx :: map()) ::
              {:ok, binary()} | :keep
  @callback reset(type :: byte()) :: :ok | {:error, byte()}
  @callback run_idle_changed(conn_info :: map(), :run | :idle) :: :ok
  @callback connection_event(conn_info :: map(), :opened | :closed | :timeout) :: :ok

  defmacro __using__(_opts) do
    quote do
      @behaviour Eipex.Adapter.Handler

      def after_assembly_write(_instance, _data, _ctx), do: :ok
      def before_assembly_read(_instance, _ctx), do: :keep
      def reset(_type), do: :ok
      def run_idle_changed(_conn_info, _mode), do: :ok
      def connection_event(_conn_info, _event), do: :ok

      defoverridable after_assembly_write: 3,
                     before_assembly_read: 2,
                     reset: 1,
                     run_idle_changed: 2,
                     connection_event: 2
    end
  end
end

defmodule Eipex.Adapter.Handler.Default do
  @moduledoc false
  use Eipex.Adapter.Handler
end
