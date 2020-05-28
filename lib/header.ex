defmodule Alcyone.Header do
  alias Alcyone.Header.{VersionNegotiation, Initial}

  use Bitwise

  # 1 bit = long header, 0 bite = short header

  # Long Header Packet {
  #   Header Form (1) = 1,
  #   Fixed Bit (1) = 1,
  #   Long Packet Type (2),
  #   Type-Specific Bits (4),
  #   Version (32),
  #   DCID Length (8),
  #   Destination Connection ID (0..160),
  #   SCID Length (8),
  #   Source Connection ID (0..160),
  # }

  # 0x0 	Initial
  # 0x1 	0-RTT
  # 0x2 	Handshake
  # 0x3 	Retry

  @valid_versions [
    # draft 28
    0xFF00001C
  ]

  @dcid_length 0..160

  @scid_length 0..160

  @dcid_version_length 0..2040

  @scid_version_length 0..2040

  # version negotation packet, only when version == 0
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
  def decode(
        <<1::1, 1::1, _::6, 0::unsigned-integer-32, dcid_length::unsigned-integer-8,
          dcid::binary-size(dcid_length), scid_length::unsigned-integer-8,
          scid::binary-size(scid_length), rest::binary>>
      )
      when dcid_length in @dcid_version_length and
             scid_length in @scid_version_length do
    supported_versions = decode_u32_list(rest, [])

    %VersionNegotiation{dcid: dcid, scid: scid, supported_version: supported_versions}
  end

  #  0x0 	Initial
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
        <<1::1, 1::1, 0x0::2, _reserved_bytes::4, version::unsigned-integer-32,
          dcid_length::unsigned-integer-8, dcid::binary-size(dcid_length),
          scid_length::unsigned-integer-8, scid::binary-size(scid_length), rest::binary>>
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
    {token_length, token_var_size} = decode_var_int(rest)
    # ignore the rest since is only valid once the header is decrypted
    <<_::binary-size(token_var_size), token::binary-size(token_length), _rest::binary>> = rest

    # 56 is the fixed amount of bytes read
    bytes_read = 56 + dcid_length + scid_length + token_var_size + token_length

    %Initial{
      version: version,
      dcid: dcid,
      scid: scid,
      token: token,
      bytes_read: bytes_read
    }
  end

  #  0x1 	0-RTT
  def decode(
        <<1::1, 1::1, 0x1::2, _type_specific::4, version::unsigned-integer-32,
          dcid_length::unsigned-integer-8, _dcid::binary-size(dcid_length),
          scid_length::unsigned-integer-8, _scid::binary-size(scid_length), _rest::binary>>
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
    # TODO erlang tls 1.3 does not support 0-rtt just yet so not sure about this one
  end

  #  0x2 	Handshake
  def decode(
        <<1::1, 1::1, 0x2::2, _type_specific::4, version::unsigned-integer-32,
          dcid_length::unsigned-integer-8, _dcid::binary-size(dcid_length),
          scid_length::unsigned-integer-8, _scid::binary-size(scid_length), _rest::binary>>
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
  end

  #  0x3 	Retry
  def decode(
        <<1::1, 1::1, 0x3::2, _type_specific::4, version::unsigned-integer-32,
          dcid_length::unsigned-integer-8, _dcid::binary-size(dcid_length),
          scid_length::unsigned-integer-8, _scid::binary-size(scid_length), _rest::binary>>
      )
      when version in @valid_versions and dcid_length in @dcid_length and
             scid_length in @scid_length do
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

  # we should keep this here, to allow binary optimization!
  # TODO maybe implementing this as a `using macro` allow us to reuse the code while allowing optimization?
  defp decode_u32_list(<<item::unsigned-integer-32, rest::binary>>, list) do
    decode_u32_list(rest, [item | list])
  end

  defp decode_u32_list(<<>>, list) do
    list
  end

  # 0 == 1 length
  def decode_var_int(<<0::2, _::6, _::binary>> = binary) do
    <<value::8, _rest::binary>> = binary

    # Mask the 2 most significant bits to remove the encoded length.
    {value &&& 0x3F, 1}
  end

  # 1 == 2 length
  def decode_var_int(<<1::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::8, _rest::binary>> = binary

    <<value::integer-16>> = <<header &&& 0x3F, remaining>>

    {value, 2}
  end

  # 2 == 4 length
  def decode_var_int(<<2::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::binary-3, _rest::binary>> = binary

    <<value::integer-32>> = <<header &&& 0x3F, remaining::binary>>

    {value, 4}
  end

  # 3 == 8 length
  def decode_var_int(<<3::2, _::6, _::binary>> = binary) do
    <<header::8, remaining::binary-7, _rest::binary>> = binary

    <<value::integer-64>> = <<header &&& 0x3F, remaining::binary>>

    {value, 8}
  end
end
