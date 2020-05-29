defmodule Alcyone.Header.Decoder do
  @moduledoc """
  UDP Datagram decoder for QUIC header format
  """
  alias Alcyone.Header.Types.{VersionNegotiation, Initial, ZeroRtt, Handshake, Retry, Short}

  use Bitwise

  # TODO I'm not sure if we want to abstract the parsing based on the version... This only makes sense for invariants
  # but why do we want to support invariants?
  @valid_versions [
    # draft 28
    0xFF00001C
  ]

  @short_header_signature <<0::1, 1::1>>

  @long_header_signature <<1::1, 1::1>>

  @initial_signature <<0x0::2>>

  @zerortt_signature <<0x1::2>>

  @handshake_signature <<0x2::2>>

  @retry_signature <<0x3::2>>

  @dcid_length 0..160

  @scid_length 0..160

  @dcid_version_length 0..2040

  @scid_version_length 0..2040

  # 56 is the fixed amount of bytes read
  @fixed_header_bytes 56

  # Version Negotiation Packet {
  #   Header Form (1) = 1,
  #   Unused (7),
  #   Version (32) = 0,
  #   DCID Length (8),
  #   Destination Connection ID (0..2040),
  #   SCID Length (8),
  #   Source Connection ID (0..2040),
  #   Supported Version (32) ...,
  # }
  @spec decode(binary(), non_neg_integer()) ::
          :error
          | VersionNegotiation.t()
          | Initial.t()
          | ZeroRtt.t()
          | Handshake.t()
          | Retry.t()
          | Short.t()
  def decode(
        <<@long_header_signature, _::6, 0::unsigned-integer-32, dcid_length::unsigned-integer-8,
          dcid::binary-size(dcid_length), scid_length::unsigned-integer-8,
          scid::binary-size(scid_length), rest::binary>>,
        _local_cid_len
      )
      when dcid_length in @dcid_version_length and
             scid_length in @scid_version_length do
    supported_versions = decode_u32_list(rest, [])

    %VersionNegotiation{dcid: dcid, scid: scid, supported_version: supported_versions}
  end

  # Initial Packet {
  #   Header Form (1) = 1,
  #   Fixed Bit (1) = 1,
  #   Long Packet Type (2) = 0,
  #   Reserved Bits (2),         # Protected
  #   Packet Number Length (2),  # Protected
  #   Version (32),
  #   DCID Len (8),
  #   Destination Connection ID (0..160),
  #   SCID Len (8),
  #   Source Connection ID (0..160),
  #   Token Length (i),
  #   Token (..),
  #   Packet Number (8..32),     # Protected
  #   Protected Payload (0..24), # Skipped Part
  #   Protected Payload (128),   # Sampled Part
  #   Protected Payload (..)     # Remainder
  # }
  def decode(
        # we dont read packet number length since is encrypted
        <<@long_header_signature, @initial_signature, _reserved_bytes::4,
          version::unsigned-integer-32, dcid_length::unsigned-integer-8,
          dcid::binary-size(dcid_length), scid_length::unsigned-integer-8,
          scid::binary-size(scid_length), rest::binary>>,
        _local_cid_len
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
    {token_length, token_var_size} = decode_var_int(rest)
    # ignore the rest since is only valid once the header is decrypted
    <<_::binary-size(token_var_size), token::binary-size(token_length), _rest::binary>> = rest

    bytes_read = @fixed_header_bytes + dcid_length + scid_length + token_var_size + token_length

    %Initial{
      version: version,
      dcid: dcid,
      scid: scid,
      token: token,
      bytes_read: bytes_read
    }
  end

  # 0-RTT Packet {
  #   Header Form (1) = 1,
  #   Fixed Bit (1) = 1,
  #   Long Packet Type (2) = 1,
  #   Reserved Bits (2),
  #   Packet Number Length (2),
  #   Version (32),
  #   DCID Length (8),
  #   Destination Connection ID (0..160),
  #   SCID Length (8),
  #   Source Connection ID (0..160),
  #   Length (i),
  #   Packet Number (8..32),
  #   Packet Payload (..),
  # }
  def decode(
        <<@long_header_signature, @zerortt_signature, _type_specific::4,
          version::unsigned-integer-32, dcid_length::unsigned-integer-8,
          dcid::binary-size(dcid_length), scid_length::unsigned-integer-8,
          scid::binary-size(scid_length), _rest::binary>>,
        _local_cid_len
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
    # TODO erlang tls 1.3 does not support 0-rtt just yet so not sure about this one

    bytes_read = @fixed_header_bytes + dcid_length + scid_length

    %ZeroRtt{
      version: version,
      dcid: dcid,
      scid: scid,
      bytes_read: bytes_read
    }
  end

  #  0x2 	Handshake
  # Handshake Packet {
  #   Header Form (1) = 1,
  #   Fixed Bit (1) = 1,
  #   Long Packet Type (2) = 2,
  #   Reserved Bits (2),
  #   Packet Number Length (2),
  #   Version (32),
  #   DCID Length (8),
  #   Destination Connection ID (0..160),
  #   SCID Length (8),
  #   Source Connection ID (0..160),
  #   Length (i),
  #   Packet Number (8..32),
  #   Packet Payload (..),
  # }
  def decode(
        <<@long_header_signature, @handshake_signature, _type_specific::4,
          version::unsigned-integer-32, dcid_length::unsigned-integer-8,
          dcid::binary-size(dcid_length), scid_length::unsigned-integer-8,
          scid::binary-size(scid_length), _rest::binary>>,
        _local_cid_len
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
    bytes_read = @fixed_header_bytes + dcid_length + scid_length

    %Handshake{
      version: version,
      dcid: dcid,
      scid: scid,
      bytes_read: bytes_read
    }
  end

  #  0x3 	Retry
  # Retry Packet {
  #   Header Form (1) = 1,
  #   Fixed Bit (1) = 1,
  #   Long Packet Type (2) = 3,
  #   Unused (4),
  #   Version (32),
  #   DCID Length (8),
  #   Destination Connection ID (0..160),
  #   SCID Length (8),
  #   Source Connection ID (0..160),
  #   Retry Token (..),
  #   Retry Integrity Tag (128),
  # }
  def decode(
        <<@long_header_signature, @retry_signature, _type_specific::4,
          version::unsigned-integer-32, dcid_length::unsigned-integer-8,
          dcid::binary-size(dcid_length), scid_length::unsigned-integer-8,
          scid::binary-size(scid_length), rest::binary>>,
        _local_cid_len
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
    # TODO binary created...
    rest_len = byte_size(rest)

    if rest_len < 16 do
      # TODO handle errors correctly
      :error
    else
      token_len = rest_len - 16
      <<token::binary-size(token_len), _rest1::binary>> = rest

      bytes_read = @fixed_header_bytes + dcid_length + scid_length + token_len

      %Retry{
        version: version,
        dcid: dcid,
        scid: scid,
        token: token,
        bytes_read: bytes_read
      }
    end
  end

  # Short Header Packet {
  #   Header Form (1) = 0,
  #   Fixed Bit (1) = 1,
  #   Spin Bit (1),
  #   Reserved Bits (2),         # Protected
  #   Key Phase (1),             # Protected
  #   Packet Number Length (2),  # Protected
  #   Destination Connection ID (0..160),
  #   Packet Number (8..32),     # Protected
  #   Protected Payload (0..24), # Skipped Part
  #   Protected Payload (128),   # Sampled Part
  #   Protected Payload (..),    # Remainder
  # }
  def decode(<<@short_header_signature, spin_bit::1, _protected::5, rest::binary>>, local_cid_len) do
    <<dcid::binary-size(local_cid_len), _rest::binary>> = rest

    bytes_read = 8 + local_cid_len

    %Short{
      spin_bit: spin_bit,
      dcid: dcid,
      bytes_read: bytes_read
    }
  end

  # TODO maybe implementing this as a `using macro` allow us to reuse the code while allowing optimization?

  # we should keep this here, to allow binary optimization!
  defp decode_u32_list(<<item::unsigned-integer-32, rest::binary>>, list) do
    decode_u32_list(rest, [item | list])
  end

  defp decode_u32_list(<<>>, list) do
    list
  end

  # 0 == 1 bytes length
  defp decode_var_int(<<0::2, _::6, _::binary>> = binary) do
    <<value::8, _rest::binary>> = binary

    {mask_var_int_byte(value), 1}
  end

  # 1 == 2 bytes length
  defp decode_var_int(<<1::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::8, _rest::binary>> = binary

    <<value::integer-16>> = <<mask_var_int_byte(header), remaining>>

    {value, 2}
  end

  # 2 == 4 bytes length
  defp decode_var_int(<<2::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::binary-3, _rest::binary>> = binary

    <<value::integer-32>> = <<mask_var_int_byte(header), remaining::binary>>

    {value, 4}
  end

  # 3 == 8 bytes length
  defp decode_var_int(<<3::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::binary-7, _rest::binary>> = binary

    <<value::integer-64>> = <<mask_var_int_byte(header), remaining::binary>>

    {value, 8}
  end

  # Mask the 2 most significant bits to remove the encoded length.
  defp mask_var_int_byte(value), do: value &&& 0x3F
end
