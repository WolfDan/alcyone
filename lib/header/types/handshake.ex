defmodule Alcyone.Header.Types.Handshake do
  @moduledoc """
  Represents the Handshake packet
  """
  use TypedStruct

  typedstruct do
    field :version, non_neg_integer(), enforce: true
    field :dcid, binary(), enforce: true
    field :scid, binary(), enforce: true

    # the amount of read bytes, we do this to avoid allocating the remaining bytes after reading the non encrypted packet
    field :bytes_read, non_neg_integer(), enforce: true

    # decrypt only
    field :packet_number_length, non_neg_integer()
  end
end
