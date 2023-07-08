// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/crypto/pkcs7/types.h"
#include "simple_asn1/crypto/x509/types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto::pkcs7::authenticode
{
template<typename RangeType>
using spc_pe_image_flags = bit_string<RangeType>;

template<typename RangeType>
struct spc_serialized_object
{
	RangeType class_id;
	RangeType serialized_data;
};

using spc_string_type = std::variant<std::u16string, std::string>;
template<typename RangeType>
using spc_link_type = std::variant<std::string,
	spc_serialized_object<RangeType>, spc_string_type>;

template<typename RangeType>
struct spc_pe_image_data
{
	std::optional<spc_pe_image_flags<RangeType>> flags;
	std::optional<spc_link_type<RangeType>> file;
};

template<typename RangeType>
struct spc_attribute_type_and_optional_value
{
	object_identifier_type type;
	spc_pe_image_data<RangeType> value;
};

template<typename RangeType>
struct digest_info
{
	algorithm_identifier<RangeType> digest_algorithm;
	RangeType digest;
};

template<typename RangeType>
struct spc_indirect_data_content
{
	spc_attribute_type_and_optional_value<RangeType> type_value;
	digest_info<RangeType> digest;
};

template<typename RangeType>
struct encap_content_info
{
	object_identifier_type content_type;
	spc_indirect_data_content<RangeType> content;
};

template<typename RangeType>
using content_info = content_info_base<with_raw_data<RangeType,
	encap_content_info<RangeType>>, RangeType>;
} //namespace asn1::crypto::pkcs7::authenticode
