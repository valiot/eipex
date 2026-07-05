defmodule Eipex.Adapter.Object do
  @moduledoc """
  Behaviour for CIP object classes served by the adapter's Message Router.

  Return `{:reply, data}` for a success response, `{:error, status, extended}`
  for a CIP error, or `{:raw, response}` when the module already built the
  complete Message Router response (Unconnected Send replies with the
  embedded response verbatim).
  """

  @callback handle_service(
              service :: byte(),
              instance :: non_neg_integer(),
              path_rest :: [Eipex.CIP.Path.segment()],
              data :: binary(),
              ctx :: map()
            ) ::
              {:reply, binary()} | {:raw, binary()} | {:error, byte(), [non_neg_integer()]}
end
