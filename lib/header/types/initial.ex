defmodule Alcyone.Header.Types.Initial do
  @moduledoc """
  Represents the Initial packet
  """
  use TypedStruct

  typedstruct do
    field :version, non_neg_integer(), enforce: true
    field :dcid, binary(), enforce: true
    field :scid, binary(), enforce: true
    field :token, binary(), enforce: true

    # the amount of read bytes, we do this to avoid allocating the remaining bytes after reading the non encrypted packet
    field :bytes_read, non_neg_integer(), enforce: true

    # decrypt only
    field :packet_number_length, non_neg_integer()
  end
end
