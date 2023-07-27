// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>

namespace asn1::crypto::pkcs9
{
constexpr std::array oid_timestamp_token = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 9u, 16u, 2u, 14u
});

constexpr std::array oid_counter_signature = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 9u, 6u
});

constexpr std::array oid_tst_info = std::to_array<std::uint32_t>({
	1u, 2u, 840u, 113549u, 1u, 9u, 16u, 1u, 4u
});

} //namespace asn1::crypto::pkcs9
