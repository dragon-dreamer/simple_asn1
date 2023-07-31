// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/crypto/pkcs7/types.h"
#include "simple_asn1/crypto/x509/extensions_types.h"
#include "simple_asn1/crypto/x509/types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto::pkcs7::cms
{

template<typename RangeType>
struct issuer_serial
{
    x509::ext::general_names<RangeType> issuer;
    RangeType serial;
    std::optional<bit_string<RangeType>> issuer_uid;
};

struct attr_cert_validity_period
{
    generalized_time not_before_time;
    generalized_time not_after_time;
};

template<typename RangeType>
struct attribute_certificate_info_v1
{
    std::int32_t version;
    std::variant<issuer_serial<RangeType>,
        x509::ext::general_names<RangeType>> subject;
    x509::ext::general_names<RangeType> issuer;
    algorithm_identifier<RangeType> signature;
    RangeType serial_number;
    attr_cert_validity_period cert_validity_period;
    std::vector<attribute<RangeType>> attributes;
    std::optional<bit_string<RangeType>> issuer_unique_id;
    std::optional<x509::extensions_type<RangeType>> extensions;
};

template<typename RangeType>
struct attribute_certificate_v1
{
    attribute_certificate_info_v1<RangeType> ac_info;
    algorithm_identifier<RangeType> signature_algorithm;
    bit_string<RangeType> signature;
};

enum class digest_object_type
{
    public_key = 0,
    public_key_cert = 1,
    other_object_types = 2
};

template<typename RangeType>
struct object_digest_info
{
    digest_object_type digest_obj_type;
    std::optional<object_identifier_type> other_object_type_id;
    algorithm_identifier<RangeType> digest_algorithm;
    bit_string<RangeType> object_digest;
};

template<typename RangeType>
struct holder
{
    std::optional<issuer_serial<RangeType>> base_certificate_id;
    std::optional<x509::ext::general_names<RangeType>> entity_name;
    std::optional<object_digest_info<RangeType>> obj_digest_info;
};

template<typename RangeType>
struct v2_form
{
    std::optional<x509::ext::general_names<RangeType>> issuer_name;
    std::optional<issuer_serial<RangeType>> base_certificate_id;
    std::optional<object_digest_info<RangeType>> obj_digest_info;
};

template<typename RangeType>
using attr_cert_issuer_type = std::variant<
    x509::ext::general_names<RangeType>,
    v2_form<RangeType>
>;

template<typename RangeType>
struct attribute_certificate_info
{
    std::int32_t version;
    holder<RangeType> holder_value;
    attr_cert_issuer_type<RangeType> issuer;
    algorithm_identifier<RangeType> signature;
    RangeType serial_number;
    attr_cert_validity_period cert_validity_period;
    attributes_type<RangeType> attributes;
    std::optional<bit_string<RangeType>> issuer_unique_id;
    std::optional<x509::extensions_type<RangeType>> extensions;
};

template<typename RangeType>
struct attribute_certificate
{
    attribute_certificate_info<RangeType> acinfo;
    algorithm_identifier<RangeType> signature_algorithm;
    bit_string<RangeType> signature_value;
};

template<typename RangeType>
struct other_certificate_format
{
    object_identifier_type other_cert_format;
    RangeType other_cert;
};

template<typename RangeType>
using attribute_certificate_v2_type = attribute_certificate<RangeType>;

template<typename RangeType>
using certificate_choices_type = std::variant<
    x509::certificate<RangeType>,
    x509::certificate<RangeType>,
    attribute_certificate_v1<RangeType>,
    attribute_certificate_v2_type<RangeType>,
    other_certificate_format<RangeType>
>;

template<typename RangeType>
using certificate_set_type = std::vector<certificate_choices_type<RangeType>>;

namespace ms_bug_workaround
{
template<typename RangeType>
using certificate_choices_type = std::variant<
    x509::certificate<RangeType>,
    x509::certificate<RangeType>,
    attribute_certificate_v2_type<RangeType>,
    other_certificate_format<RangeType>
>;

template<typename RangeType>
using certificate_set_type = std::vector<certificate_choices_type<RangeType>>;
} //namespace ms_bug_workaround

template<typename RangeType>
using signer_identifier_type = std::variant<
    issuer_and_serial_number<RangeType>,
    RangeType //subjectKeyIdentifier
>;

template<typename RangeType>
struct signer_info
{
    std::int32_t version;
    signer_identifier_type<RangeType> sid;
    algorithm_identifier<RangeType> digest_algorithm;
    std::optional<with_raw_data<RangeType, attributes_type<RangeType>>> authenticated_attributes;
    algorithm_identifier<RangeType> digest_encryption_algorithm;
    RangeType encrypted_digest;
    std::optional<attributes_type<RangeType>> unauthenticated_attributes;
};

template<typename RangeType>
using signer_infos_type = std::vector<signer_info<RangeType>>;

template<typename ContentInfo, template<typename> typename CertificateSet, typename RangeType>
struct signed_data_base
{
    std::int32_t version;
    algorithm_identifiers_type<RangeType> digest_algorithms;
    ContentInfo content_info;
    std::optional<CertificateSet<RangeType>> certificates;
    // std::optional<revocation_info_choices<RangeType>> // crls are not implemented
    signer_infos_type<RangeType> signer_infos;
};

template<typename ContentInfo, typename RangeType>
struct content_info_base
{
    object_identifier_type content_type;
    signed_data_base<ContentInfo, certificate_set_type, RangeType> data;
};

namespace ms_bug_workaround
{
template<typename ContentInfo, typename RangeType>
struct content_info_base
{
    object_identifier_type content_type;
    signed_data_base<ContentInfo, certificate_set_type, RangeType> data;
};
} //namespace ms_bug_workaround

} //namespace asn1::crypto::pkcs7::cms
