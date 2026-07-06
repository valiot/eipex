defmodule Eipex.Tag do
  @moduledoc """
  One tag's read result, as produced by `Eipex.Scanner.Logix.read/2,3`.

  `value`/`type` are set and `error` is `nil` on a successful decode; on
  failure `error` carries the reason (`{:cip, status_name, extended}` for a
  CIP-level rejection, or a `Eipex.Scanner.Logix.Value.decode_reply/2` error
  reason such as `:nesting_too_deep`) and `value`/`type` are `nil`. A tag
  result never raises — per-tag failures are reported here instead of
  crashing a bulk read.
  """

  defstruct [:name, :value, :type, :error]

  @type t :: %__MODULE__{
          name: String.t(),
          value: term(),
          type: term(),
          error: nil | term()
        }
end
