// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/crypto/x509/extensions_types.h"
#include "simple_asn1/crypto/x509/types.h"

namespace asn1::crypto::tst
{

struct accuracy
{
    std::optional<std::int64_t> seconds;
    std::optional<std::int32_t> millis;
    std::optional<std::int32_t> micros;
};

template<typename RangeType>
struct message_imprint
{
    algorithm_identifier<RangeType> hash_algorithm;
    RangeType hashed_message;
};

template<typename RangeType>
struct tst_info
{
    std::int32_t version;
    object_identifier_type tsa_policy_id;
    message_imprint<RangeType> imprint;
    RangeType serial_number;
    generalized_time gen_time;
    std::optional<accuracy> accuracy_val;
    bool ordering;
    std::optional<RangeType> nonce;
    std::optional<x509::ext::general_name<RangeType>> tsa;
    std::optional<x509::extensions_type<RangeType>> exts;
};

template<typename RangeType>
struct encap_tst_info
{
    object_identifier_type content_type;
    tst_info<RangeType> info;
};

} //namespace asn1::crypto::tst
