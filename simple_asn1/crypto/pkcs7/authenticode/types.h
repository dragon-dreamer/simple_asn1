// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "simple_asn1/crypto/crypto_common_types.h"
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
using algorithm_identifiers_type = std::vector<algorithm_identifier<RangeType>>;

template<typename RangeType>
using extended_certificates_and_certificate_type
	= std::variant<x509::certificate<RangeType>, x509::certificate<RangeType>>;

template<typename RangeType>
using extended_certificates_and_certificates_type
	= std::vector<extended_certificates_and_certificate_type<RangeType>>;

template<typename RangeType>
struct issuer_and_serial_number
{
	name_type<RangeType> issuer;
	RangeType serial_number;
};

template<typename RangeType>
struct attribute
{
	object_identifier_type type;
	std::vector<RangeType> values;
};

template<typename RangeType>
using attributes_type = std::vector<attribute<RangeType>>;

template<typename RangeType>
struct signer_info
{
	std::int32_t version;
	issuer_and_serial_number<RangeType> issuer_and_sn;
	algorithm_identifier<RangeType> digest_algorithm;
	std::optional<attributes_type<RangeType>> authenticated_attributes;
	algorithm_identifier<RangeType> digest_encryption_algorithm;
	RangeType encrypted_digest;
	std::optional<attributes_type<RangeType>> unauthenticated_attributes;
};

template<typename RangeType>
using signer_infos_type = std::vector<signer_info<RangeType>>;

template<typename RangeType>
struct signed_data
{
	std::int32_t version;
	algorithm_identifiers_type<RangeType> digest_algorithms;
	encap_content_info<RangeType> content_info;
	std::optional<extended_certificates_and_certificates_type<RangeType>> certificates;
	//std::optional<RangeType> crls; //Not used
	signer_infos_type<RangeType> signer_infos;
};

template<typename RangeType>
struct content_info
{
	object_identifier_type content_type;
	signed_data<RangeType> data;
};
} //namespace asn1::crypto::pkcs7::authenticode
