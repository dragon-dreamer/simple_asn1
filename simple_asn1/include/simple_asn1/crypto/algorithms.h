// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto
{
template<std::uint32_t... Components>
constexpr auto id_ansi_x9_57 = std::to_array<std::uint32_t>({ 1, 2, 840, 10040, Components... });
template<std::uint32_t... Components>
constexpr auto id_ansi_x9_62 = std::to_array<std::uint32_t>({ 1, 2, 840, 10045, Components... });
template<std::uint32_t... Components>
constexpr auto id_ansi_x9_42 = std::to_array<std::uint32_t>({ 1, 2, 840, 10046, Components... });

namespace signature
{
constexpr auto id_sha1_with_rsa_encryption = id_pkcs1<5>;
constexpr auto id_sha256_with_rsa_encryption = id_pkcs1<11>;
constexpr auto id_sha384_with_rsa_encryption = id_pkcs1<12>;
constexpr auto id_sha512_with_rsa_encryption = id_pkcs1<13>;
constexpr auto id_sha224_with_rsa_encryption = id_pkcs1<14>;
} //namespace signature

namespace pki
{
constexpr auto id_dsa = id_ansi_x9_57<4, 1>;
constexpr auto id_ec_public_key = id_ansi_x9_62<2, 1>;
constexpr auto id_dh_public_number = id_ansi_x9_42<2, 1>;
constexpr auto id_rsa = std::to_array<std::uint32_t>({
	1, 2, 840, 113549, 1, 1, 1 });
} //namespace pki

namespace hash
{
constexpr auto id_sha1 = std::to_array<std::uint32_t>({
	1u, 3u, 14u, 3u, 2u, 26u });
constexpr auto id_sha256 = std::to_array<std::uint32_t>({
	2u, 16u, 840u, 1u, 101u, 3u, 4u, 2u, 1u });
constexpr auto id_sha384 = std::to_array<std::uint32_t>({
	2u, 16u, 840u, 1u, 101u, 3u, 4u, 2u, 2u });
constexpr auto id_sha512 = std::to_array<std::uint32_t>({
	2u, 16u, 840u, 1u, 101u, 3u, 4u, 2u, 3u });
constexpr auto id_md5 = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 2u, 5u });
} //namespace hash

} //namespace asn1::crypto
