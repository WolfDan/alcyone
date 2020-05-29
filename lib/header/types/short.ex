defmodule Alcyone.Header.Types.Short do
  @moduledoc """
  Represents the ZeroRtt packet
  """
  use TypedStruct

  typedstruct do
    field :spin_bit, integer(), enforce: true
    field :dcid, binary(), enforce: true

    # the amount of read bytes, we do this to avoid allocating the remaining bytes after reading the non encrypted packet
    field :bytes_read, non_neg_integer(), enforce: true

    # decrypt only
    field :packet_number_length, non_neg_integer()
  end
end
