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
} //namespace asn1::crypto::pkcs7
