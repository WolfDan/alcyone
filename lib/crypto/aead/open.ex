defmodule Alcyone.Crypto.Aead.Open do
  @moduledoc """
  Describes an open public aead key
  """
  alias Alcyone.Crypto.Utils
  use TypedStruct

  typedstruct do
    field :cipher, atom(), enforce: true
    field :key, binary(), enforce: true
    field :iv, binary(), enforce: true
    field :hp_key, binary(), enforce: true
    field :algo, atom(), enforce: true
  end

  def new(algo, key, iv, hp_key) do
    %__MODULE__{
      cipher: Utils.aead_to_crypto(algo),
      key: key,
      iv: iv,
      hp_key: hp_key,
      algo: algo
    }
  end

  def new_mask(%__MODULE__{cipher: cipher, hp_key: hp_key}, sample) do
    <<result::binary-size(5), _rest::binary>> =
      :crypto.crypto_one_time(cipher, hp_key, sample, [{:encrypt, true}])

    result
  end
end
