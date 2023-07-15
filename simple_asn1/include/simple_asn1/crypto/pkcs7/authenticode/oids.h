// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace asn1::crypto::pkcs7::authenticode
{
constexpr std::array page_hashes_class_id{
	std::byte{0xa6u},
	std::byte{0xb5u},
	std::byte{0x86u},
	std::byte{0xd5u},
	std::byte{0xb4u},
	std::byte{0xa1u},
	std::byte{0x24u},
	std::byte{0x66u},
	std::byte{0xaeu},
	std::byte{0x05u},
	std::byte{0xa2u},
	std::byte{0x17u},
	std::byte{0xdau},
	std::byte{0x8eu},
	std::byte{0x60u},
	std::byte{0xd6u}
};

constexpr std::array oid_spc_page_hash_v1 = std::to_array<std::uint32_t>({
	1u, 3u, 6u, 1u, 4u, 1u, 311u, 2u, 3u, 1u
});
constexpr std::array oid_spc_page_hash_v2 = std::to_array<std::uint32_t>({
	1u, 3u, 6u, 1u, 4u, 1u, 311u, 2u, 3u, 2u
});
constexpr std::array oid_spc_indirect_data_content = std::to_array<std::uint32_t>({
	1u, 3u, 6u, 1u, 4u, 1u, 311u, 2u, 1u, 4u
});
constexpr std::array oid_spc_pe_image_data = std::to_array<std::uint32_t>({
	1u, 3u, 6u, 1u, 4u, 1u, 311u, 2u, 1u, 15u
});
constexpr std::array oid_nested_signature_attribute = std::to_array<std::uint32_t>({
	1u, 3u, 6u, 1u, 4u, 1u, 311u, 2u, 4u, 1u
});
constexpr std::array oid_spc_sp_opus_info = std::to_array<std::uint32_t>({
	1u, 3u, 6u, 1u, 4u, 1u, 311u, 2u, 1u, 12u
});
} //namespace asn1::crypto::pkcs7::authenticode
