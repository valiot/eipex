defmodule Eipex.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Eipex.CIP.{Path, Types}

  property "logical EPATH segments round-trip" do
    check all(
            class <- integer(0..0xFFFF),
            instance <- integer(0..0xFFFF),
            attribute <- integer(0..0xFF)
          ) do
      segs = [{:class, class}, {:instance, instance}, {:attribute, attribute}]
      assert {:ok, ^segs} = segs |> Path.encode() |> Path.decode()
    end
  end

  property "symbolic EPATH segments round-trip" do
    check all(name <- string(:alphanumeric, min_length: 1, max_length: 255)) do
      assert {:ok, [{:symbolic, ^name}]} = Path.encode(symbolic: name) |> Path.decode()
    end
  end

  property "atomic CIP values round-trip through encode/decode" do
    check all(
            {type, value} <-
              one_of([
                tuple({constant(:sint), integer(-128..127)}),
                tuple({constant(:int), integer(-32_768..32_767)}),
                tuple({constant(:dint), integer(-2_147_483_648..2_147_483_647)}),
                tuple({constant(:udint), integer(0..4_294_967_295)}),
                tuple({constant(:real), float()})
              ])
          ) do
      {:ok, bin} = Types.encode(type, value)
      {:ok, decoded} = Types.decode(type, bin)

      if type == :real do
        assert_in_delta decoded, value, abs(value) * 1.0e-6 + 1.0e-30
      else
        assert decoded == value
      end
    end
  end
end
