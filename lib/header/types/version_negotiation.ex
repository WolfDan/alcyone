defmodule Alcyone.Header.Types.VersionNegotiation do
  @moduledoc """
  Represents the version negotiation header packet
  """
  use TypedStruct

  typedstruct do
    field :dcid, binary(), enforce: true
    field :scid, binary(), enforce: true
    field :supported_version, list(non_neg_integer()), enforce: true
  end
end
