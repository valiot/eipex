defmodule Eipex.CIP.Types do
  @moduledoc """
  CIP elementary data type codec and the Logix 16-bit symbol type decoder
  (1756-PM020). Structures arrive as `0x02A0` + template handle; their
  interpretation needs the Template object (see Eipex.CIP.Logix).
  """

  @codes [
    bool: 0xC1,
    sint: 0xC2,
    int: 0xC3,
    dint: 0xC4,
    lint: 0xC5,
    usint: 0xC6,
    uint: 0xC7,
    udint: 0xC8,
    ulint: 0xC9,
    real: 0xCA,
    lreal: 0xCB,
    byte: 0xD1,
    word: 0xD2,
    dword: 0xD3,
    lword: 0xD4,
    short_string: 0xDA
  ]

  @spec type_code(atom()) :: non_neg_integer()
  def type_code(name), do: Keyword.fetch!(@codes, name)

  @spec type_name(non_neg_integer()) :: atom()
  def type_name(code) do
    Enum.find_value(@codes, :unknown, fn {name, c} -> if c == code, do: name end)
  end

  @spec encode(atom(), term()) :: {:ok, binary()} | {:error, :bad_value}
  def encode(:bool, true), do: {:ok, <<1>>}
  def encode(:bool, false), do: {:ok, <<0>>}
  def encode(:sint, v) when v in -128..127, do: {:ok, <<v::8-signed>>}
  def encode(:int, v) when v in -32_768..32_767, do: {:ok, <<v::16-little-signed>>}
  def encode(:dint, v) when v in -2_147_483_648..2_147_483_647, do: {:ok, <<v::32-little-signed>>}

  def encode(:lint, v) when v in -9_223_372_036_854_775_808..9_223_372_036_854_775_807,
    do: {:ok, <<v::64-little-signed>>}

  def encode(:usint, v) when v in 0..255, do: {:ok, <<v::8>>}
  def encode(:uint, v) when v in 0..65_535, do: {:ok, <<v::16-little>>}
  def encode(:udint, v) when v in 0..4_294_967_295, do: {:ok, <<v::32-little>>}
  def encode(:ulint, v) when v in 0..18_446_744_073_709_551_615, do: {:ok, <<v::64-little>>}

  def encode(:real, v) when is_number(v) and v >= -3.4e38 and v <= 3.4e38,
    do: {:ok, <<v::32-little-float>>}

  def encode(:lreal, v) when is_number(v), do: {:ok, <<v::64-little-float>>}
  def encode(:byte, v) when v in 0..255, do: {:ok, <<v::8>>}
  def encode(:word, v) when v in 0..65_535, do: {:ok, <<v::16-little>>}
  def encode(:dword, v) when v in 0..4_294_967_295, do: {:ok, <<v::32-little>>}
  def encode(:lword, v) when v in 0..18_446_744_073_709_551_615, do: {:ok, <<v::64-little>>}

  def encode(:short_string, s) when is_binary(s) and byte_size(s) < 256,
    do: {:ok, <<byte_size(s), s::binary>>}

  def encode(_, _), do: {:error, :bad_value}

  @spec decode(atom(), binary()) :: {:ok, term()} | {:error, :bad_value}
  def decode(:bool, <<0>>), do: {:ok, false}
  def decode(:bool, <<_>>), do: {:ok, true}
  def decode(:sint, <<v::8-signed>>), do: {:ok, v}
  def decode(:int, <<v::16-little-signed>>), do: {:ok, v}
  def decode(:dint, <<v::32-little-signed>>), do: {:ok, v}
  def decode(:lint, <<v::64-little-signed>>), do: {:ok, v}
  def decode(:usint, <<v::8>>), do: {:ok, v}
  def decode(:uint, <<v::16-little>>), do: {:ok, v}
  def decode(:udint, <<v::32-little>>), do: {:ok, v}
  def decode(:ulint, <<v::64-little>>), do: {:ok, v}
  def decode(:real, <<v::32-little-float>>), do: {:ok, v}
  def decode(:real, <<bits::32-little>>), do: {:ok, non_finite(bits, 23, 0xFF)}
  def decode(:lreal, <<v::64-little-float>>), do: {:ok, v}
  def decode(:lreal, <<bits::64-little>>), do: {:ok, non_finite(bits, 52, 0x7FF)}
  def decode(:byte, <<v::8>>), do: {:ok, v}
  def decode(:word, <<v::16-little>>), do: {:ok, v}
  def decode(:dword, <<v::32-little>>), do: {:ok, v}
  def decode(:lword, <<v::64-little>>), do: {:ok, v}
  def decode(:short_string, <<len, s::binary-size(len)>>), do: {:ok, s}
  def decode(_, _), do: {:error, :bad_value}

  @doc "Parses `<<type::16-little, payload>>` from Logix read replies."
  @spec decode_typed(binary()) ::
          {:ok, {atom(), term()} | {:struct, non_neg_integer(), binary()}}
          | {:error, :bad_value}
  def decode_typed(<<0xA0, 0x02, handle::16-little, data::binary>>),
    do: {:ok, {:struct, handle, data}}

  def decode_typed(<<0xDA, 0x00, payload::binary>>) do
    case decode(:short_string, payload) do
      {:ok, s} -> {:ok, {:short_string, s}}
      error -> error
    end
  end

  def decode_typed(<<code::16-little, payload::binary>>) do
    with name when name != :unknown <- type_name(code),
         {:ok, values} <- decode_elements(name, payload, []) do
      case values do
        [single] -> {:ok, {name, single}}
        many -> {:ok, {name, many}}
      end
    else
      _ -> {:error, :bad_value}
    end
  end

  def decode_typed(_), do: {:error, :bad_value}

  defp decode_elements(_name, <<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_elements(name, payload, acc) do
    size = element_size(name)

    case payload do
      <<chunk::binary-size(size), rest::binary>> ->
        case decode(name, chunk) do
          {:ok, value} -> decode_elements(name, rest, [value | acc])
          {:error, _} = error -> error
        end

      _ ->
        {:error, :bad_value}
    end
  end

  defp element_size(name) when name in [:bool, :sint, :usint, :byte], do: 1
  defp element_size(name) when name in [:int, :uint, :word], do: 2
  defp element_size(name) when name in [:dint, :udint, :dword, :real], do: 4
  defp element_size(name) when name in [:lint, :ulint, :lword, :lreal], do: 8

  defp non_finite(bits, frac_bits, exp_mask) do
    import Bitwise
    sign_shift = frac_bits + exp_bits(exp_mask)

    cond do
      (bits &&& (1 <<< frac_bits) - 1) != 0 -> :nan
      bits >>> sign_shift == 1 -> :neg_infinity
      true -> :infinity
    end
  end

  defp exp_bits(0xFF), do: 8
  defp exp_bits(0x7FF), do: 11

  @doc "Decodes the Logix 16-bit symbol type word (1756-PM020 p.50)."
  @spec decode_symbol_type(term()) :: map() | :error
  def decode_symbol_type(<<value::16-little>>), do: decode_symbol_type(value)

  def decode_symbol_type(value) when is_integer(value) do
    import Bitwise

    structure? = (value &&& 0x8000) != 0
    system? = (value &&& 0x1000) != 0
    dims = value >>> 13 &&& 0x3

    if structure? do
      %{
        structure?: true,
        system?: system?,
        dims: dims,
        atomic_type: nil,
        template_instance: value &&& 0x0FFF,
        bool_position: nil
      }
    else
      code = value &&& 0xFF
      atomic = type_name(code)

      bool_position =
        if atomic == :bool, do: value >>> 8 &&& 0x7

      %{
        structure?: false,
        system?: system?,
        dims: dims,
        atomic_type: atomic,
        template_instance: nil,
        bool_position: bool_position
      }
    end
  end

  def decode_symbol_type(_), do: :error
end
