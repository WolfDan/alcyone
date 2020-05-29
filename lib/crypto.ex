defmodule Alcyone.Crypto do
  @moduledoc """
  Cryto helper for QUIC

  While otp 23 has tls 1.3 implementations, QUIC uses a lot of custom implementations within the crypto api

  This module is a helper for all those QUIC specific implementation
  """
  alias Alcyone.Crypto.Hkdf

  alias Alcyone.Crypto.Aead.{Open, Seal, Keys}

  # https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-initial-secrets
  @initial_salf <<0xC3, 0xEE, 0xF7, 0x12, 0xC7, 0x2E, 0xBB, 0x5A, 0x11, 0xA7, 0xD2, 0x43, 0x2B,
                  0xB4, 0x63, 0x65, 0xBE, 0xF9, 0xF5, 0x02>>

  # hard code since we use always AES128_GCM and erlang isn't as flexible with static values
  @aes128_gcm_key_len 16
  @aes128_gcm_nonce_len 12

  @client_initial_secret_label "client in"
  @server_initial_secret_label "server in"

  @label_prefix "tls13 "

  @hdr_label "quic hp"
  @pkt_key_label "quic key"
  @pkt_iv_label "quic iv"

  def derive_initial_secret(dcid) do
    # HKDF-Extract (initial_salt, client_dst_connection_id)
    Hkdf.extract(:sha256, @initial_salf, dcid)
  end

  def derive_initial_key_material(dcid, is_server?) do
    key_len = @aes128_gcm_key_len
    nonce_len = @aes128_gcm_nonce_len

    # derived from HKDF
    hash_type = :sha256

    initial_secret = derive_initial_secret(dcid)

    # Client
    secret = derive_client_initial_secret(hash_type, initial_secret, 32)

    client_key = derive_pkt_key(hash_type, secret, key_len)
    client_iv = derive_pkt_iv(hash_type, secret, nonce_len)
    client_hp_key = derive_hdr_key(hash_type, secret, key_len)

    # Server
    secret = derive_server_initial_secret(hash_type, initial_secret, 32)

    server_key = derive_pkt_key(hash_type, secret, key_len)
    server_iv = derive_pkt_iv(hash_type, secret, nonce_len)
    server_hp_key = derive_hdr_key(hash_type, secret, key_len)

    # todo, quic header protection key creation!
    if is_server? do
      %Keys{
        open: Open.new(:aes_128_gcm, client_key, client_iv, client_hp_key),
        seal: Seal.new(:aes_128_gcm, server_key, server_iv, server_hp_key)
      }
    else
      %Keys{
        open: Open.new(:aes_128_gcm, server_key, server_iv, server_hp_key),
        seal: Seal.new(:aes_128_gcm, client_key, client_iv, client_hp_key)
      }
    end
  end

  defp derive_client_initial_secret(hash_type, prk, len) do
    hkdf_expand_label(hash_type, prk, @client_initial_secret_label, len)
  end

  defp derive_server_initial_secret(hash_type, prk, len) do
    hkdf_expand_label(hash_type, prk, @server_initial_secret_label, len)
  end

  defp derive_pkt_key(hash_type, secret, aead_len) do
    <<out::binary-size(aead_len), _rest::binary>> =
      hkdf_expand_label(hash_type, secret, @pkt_key_label, aead_len)

    out
  end

  defp derive_pkt_iv(hash_type, secret, aead_len) do
    <<out::binary-size(aead_len), _rest::binary>> =
      hkdf_expand_label(hash_type, secret, @pkt_iv_label, aead_len)

    out
  end

  defp derive_hdr_key(hash_type, secret, aead_len) do
    <<out::binary-size(aead_len), _rest::binary>> =
      hkdf_expand_label(hash_type, secret, @hdr_label, aead_len)

    out
  end

  defp hkdf_expand_label(hash_type, prk, label, len) do
    # https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
    tls_label = <<
      len::unsigned-integer-16,
      byte_size(@label_prefix) + byte_size(label)::8,
      @label_prefix::binary,
      label::binary,
      # no context so size = 0
      0::8
    >>

    Hkdf.expand(hash_type, prk, len, tls_label)
  end
end
