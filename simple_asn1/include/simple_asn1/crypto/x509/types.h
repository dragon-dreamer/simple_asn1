// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto::x509
{
template<typename RangeType>
struct extension
{
	object_identifier_type extnid;
	bool critical;
	RangeType extnValue;
};

template<typename RangeType>
using extensions_type = std::vector<extension<RangeType>>;

struct validity
{
	time_type not_before;
	time_type not_after;
};

template<typename RangeType>
struct subject_public_key_info
{
	algorithm_identifier<RangeType> algorithm;
	bit_string<RangeType> subject_publickey;
};

template<typename RangeType>
struct tbs_certificate
{
	std::int32_t version;
	RangeType serial_number;
	algorithm_identifier<RangeType> signature;
	with_raw_data<RangeType, name_type<RangeType>> issuer;
	validity valid;
	name_type<RangeType> subject;
	subject_public_key_info<RangeType> pki;
	std::optional<bit_string<RangeType>> issuer_unique_id;
	std::optional<bit_string<RangeType>> subject_unique_id;
	std::optional<extensions_type<RangeType>> extensions;
};

template<typename RangeType>
struct certificate
{
	tbs_certificate<RangeType> tbs_cert;
	algorithm_identifier<RangeType> signature_algorithm;
	bit_string<RangeType> signature;
};
} //namespace asn1::crypto::x509
