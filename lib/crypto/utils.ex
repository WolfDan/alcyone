defmodule Alcyone.Crypto.Utils do
  @aead_128 [:aes_128_ccm, :aes_192_ccm, :aes_256_ccm, :aes_128_gcm, :aes_192_gcm]

  # https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-aes-based-header-protection
  def aead_to_crypto(aead) when aead in @aead_128 do
    :aes_128_ecb
  end

  def aead_to_crypto(aead) when aead == :aes_256_gcm do
    :aes_256_ecb
  end

  def aead_to_crypto(aead) when aead == :chacha20_poly1305 do
    :chacha20
  end
end
