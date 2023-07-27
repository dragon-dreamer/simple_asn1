// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>

namespace asn1::crypto::pkcs7
{
constexpr std::array oid_message_digest = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 9u, 4u
});

constexpr std::array oid_content_type = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 9u, 3u
});

constexpr std::array oid_signing_time = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 9u, 5u
});

constexpr std::array oid_signed_data = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 7u, 2u
});
} //namespace asn1::crypto::pkcs7
