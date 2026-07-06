defmodule Eipex.Adapter.Config do
  @moduledoc """
  Immutable adapter configuration handed to every session handler and
  CIP object dispatch: identity, object dispatch table, application
  handler module, assembly store, timeouts and network attributes.
  """

  defstruct identity: nil,
            objects: %{},
            handler: nil,
            store: nil,
            inactivity_timeout: 120_000,
            network: %{},
            connections: nil,
            io: nil

  @type t :: %__MODULE__{}
end
