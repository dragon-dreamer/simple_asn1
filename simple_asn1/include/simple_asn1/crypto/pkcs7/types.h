// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/crypto/x509/types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto::pkcs7
{
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
	std::optional<with_raw_data<RangeType, attributes_type<RangeType>>> authenticated_attributes;
	algorithm_identifier<RangeType> digest_encryption_algorithm;
	RangeType encrypted_digest;
	std::optional<attributes_type<RangeType>> unauthenticated_attributes;
};

template<typename RangeType>
using signer_infos_type = std::vector<signer_info<RangeType>>;

template<typename ContentInfo, typename RangeType>
struct signed_data
{
	std::int32_t version;
	algorithm_identifiers_type<RangeType> digest_algorithms;
	ContentInfo content_info;
	std::optional<extended_certificates_and_certificates_type<RangeType>> certificates;
	//std::optional<RangeType> crls; //Not implemented
	signer_infos_type<RangeType> signer_infos;
};

template<typename ContentInfo, typename RangeType>
struct content_info_base
{
	object_identifier_type content_type;
	signed_data<ContentInfo, RangeType> data;
};
} //namespace asn1::crypto::pkcs7
