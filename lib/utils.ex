defmodule Alcyone.Utils do
  use Bitwise

  # 0 == 1 length
  def decode_var_int(<<0::2, _::6, _::binary>> = binary) do
    <<value::8, _rest::binary>> = binary

    # Mask the 2 most significant bits to remove the encoded length.
    {value &&& 0x3F, 1}
  end

  # 1 == 2 length
  def decode_var_int(<<1::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::8, _rest::binary>> = binary

    <<value::integer-16>> = <<header &&& 0x3F, remaining>>

    {value, 2}
  end

  # 2 == 4 length
  def decode_var_int(<<2::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::binary-3, _rest::binary>> = binary

    <<value::integer-32>> = <<header &&& 0x3F, remaining::binary>>

    {value, 4}
  end

  # 3 == 8 length
  def decode_var_int(<<3::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::binary-7, _rest::binary>> = binary

    <<value::integer-64>> = <<header &&& 0x3F, remaining::binary>>

    {value, 8}
  end

  def decode_u32_list(<<item::unsigned-integer-32, rest::binary>>, list) do
    decode_u32_list(rest, [item | list])
  end

  def decode_u32_list(<<>>, list) do
    list
  end
end
