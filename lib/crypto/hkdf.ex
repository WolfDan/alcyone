defmodule Alcyone.Crypto.Hkdf do
  @moduledoc """
  updated version of
  https://github.com/sschneider1207/hkdf/blob/master/lib/hkdf.ex

  TODO MUST TEST CRYPTO CODE!!!!!!!
  """

  def extract(hash_type, key, data) do
    :crypto.mac(:hmac, hash_type, key, data)
  end

  def expand(hash_type, prk, len, info) do
    hash_len = hash_length(hash_type)
    n = Float.ceil(len / hash_len) |> round()

    full =
      Enum.scan(1..n, <<>>, fn index, prev ->
        data = <<prev::binary, info::binary, index::binary>>
        :crypto.mac(:hmac, hash_type, prk, data)
      end)
      |> Enum.join(<<>>)

    <<output::unit(8)-size(len), _::binary>> = full
    <<output::unit(8)-size(len)>>
  end

  for fun <- ~w(md5 sha sha224 sha256 sha384 sha512)a do
    len = fun |> :crypto.hash("") |> byte_size()

    defp hash_length(unquote(fun)) do
      unquote(len)
    end
  end
end
