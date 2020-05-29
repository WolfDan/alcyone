defmodule Alcyone.Header do
  @moduledoc """
  Coder for specific QUIC header format
  """
  @spec decode(binary(), non_neg_integer()) ::
          :error
          | VersionNegotiation.t()
          | Initial.t()
          | ZeroRtt.t()
          | Handshake.t()
          | Retry.t()
          | Short.t()
  defdelegate decode(bytes, local_cid_len), to: Alcyone.Header.Decoder
end
