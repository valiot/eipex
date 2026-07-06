defmodule Eipex.Adapter.Object do
  @moduledoc """
  Behaviour for CIP object classes served by the adapter's Message Router.

  Return `{:reply, data}` for a success response, `{:reply, data, extra_cpf}` to
  append extra CPF items to the encapsulation reply, `{:error, status, extended}`
  for a CIP error, `{:raw, response}` when the module already built the
  complete Message Router response (Unconnected Send replies with the
  embedded response verbatim), or `{:raw, response, extra_cpf}` when that
  embedded response itself carries extra CPF items (e.g. a re-dispatched
  class 1 Forward Open's `sockaddr_o2t`) that must propagate to the outer
  encapsulation reply.
  """

  @callback handle_service(
              service :: byte(),
              instance :: non_neg_integer(),
              path_rest :: [Eipex.CIP.Path.segment()],
              data :: binary(),
              ctx :: map()
            ) ::
              {:reply, binary()}
              | {:reply, binary(), [Eipex.CPF.item()]}
              | {:raw, binary()}
              | {:raw, binary(), [Eipex.CPF.item()]}
              | {:error, byte(), [non_neg_integer()]}
end
