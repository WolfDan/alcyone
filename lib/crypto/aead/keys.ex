defmodule Alcyone.Crypto.Aead.Keys do
  @moduledoc """
  Describes a pair of keys for header protection
  """
  alias Alcyone.Crypto.Aead.{Open, Seal}
  use TypedStruct

  typedstruct do
    field :open, Open.t(), enforce: true
    field :seal, Seal.t(), enforce: true
  end
end
