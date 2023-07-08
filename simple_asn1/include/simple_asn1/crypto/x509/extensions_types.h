// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto::x509::ext
{
template<std::uint32_t... Components>
constexpr auto id_ce = std::to_array<std::uint32_t>({ 2, 5, 29, Components... });
template<std::uint32_t... Components>
constexpr auto id_pe = id_pkix<1, Components...>;
template<std::uint32_t... Components>
constexpr auto id_ad = id_pkix<48, Components...>;

template<typename RangeType>
struct another_name
{
    object_identifier_type type_id;
    RangeType value;
};

struct edi_parity_name
{
    std::optional<directory_string> name_assigner;
    directory_string party_name;
};

template<typename RangeType>
using general_name = std::variant<
    another_name<RangeType>, //otherName
	std::string, //rfc822Name
    std::string, //dNSName
    or_address<RangeType>, //x400Address
    name_type<RangeType>, //directoryName
    edi_parity_name, //ediPartyName
    std::string, //uniformResourceIdentifier
    RangeType, //iPAddress
    object_identifier_type //registeredID
>;
template<typename RangeType>
using general_names = std::vector<general_name<RangeType>>;

template<typename RangeType>
using key_identifier = RangeType;

constexpr auto id_ce_authority_key_identifier = id_ce<35>;

template<typename RangeType>
struct authority_key_identifier
{
	std::optional<key_identifier<RangeType>> key_id;
    std::optional<general_names<RangeType>> authority_cert_issuer;
    std::optional<RangeType> certificate_serial_number;
};

constexpr auto id_ce_subject_key_identifier = id_ce<14>;
template<typename RangeType>
using subject_key_identifier = key_identifier<RangeType>;

constexpr auto id_ce_key_usage = id_ce<15>;
template<typename RangeType>
using key_usage = bit_string<RangeType>;
struct key_usage_bits
{
    enum value
    {
        digital_signature = 0,
        content_commitment = 1,
        key_encipherment = 2,
        data_encipherment = 3,
        key_agreement = 4,
        key_cert_sign = 5,
        crl_sign = 6,
        encipher_only = 7,
        decipher_only = 8
    };
};

constexpr auto id_ce_private_key_usage_period = id_ce<16>;
struct private_key_usage_period
{
    std::optional<generalized_time> not_before;
    std::optional<generalized_time> not_after;
};

constexpr auto id_ce_certificate_policies = id_ce<32>;
constexpr auto any_policy = id_ce<32, 0>;
template<std::uint32_t Component>
constexpr auto id_qt = id_pkix<2, Component>;
constexpr auto id_qt_cps = id_qt<1>;
constexpr auto id_qt_unotice = id_qt<2>;

template<std::uint32_t... Components>
constexpr auto id_ca_browser_forum = std::to_array<std::uint32_t>({ 2, 23, 140, Components... });
constexpr auto id_ca_browser_forum_domain_validated = id_ca_browser_forum<1, 2, 1>;
constexpr auto id_ca_browser_forum_organization_validated = id_ca_browser_forum<1, 2, 2>;
constexpr auto id_ca_browser_forum_individual_validated = id_ca_browser_forum<1, 2, 3>;
constexpr auto id_ca_browser_forum_code_signing = id_ca_browser_forum<1, 4, 1>;

constexpr auto id_google_trust_services = std::to_array<std::uint32_t>(
    { 1, 3, 6, 1, 4, 1, 11129, 2, 5, 3 });
constexpr auto id_google_internet_authority_g2 = std::to_array<std::uint32_t>(
    { 1, 3, 6, 1, 4, 1, 11129, 2, 5, 1 });

template<typename RangeType>
struct policy_qualifier_info
{
    object_identifier_type policy_qualifier_id;
    RangeType qualifier;
};
template<typename RangeType>
struct policy_information
{
    object_identifier_type policy_identifier;
    std::optional<std::vector<policy_qualifier_info<RangeType>>> policy_qualifiers;
};
using cps_uri = std::string;
using display_text = std::variant<
    std::string, //ia5String
    std::string, //visibleString
    std::u16string, //bmpString
    std::string //utf8String
>;
struct notice_reference
{
    display_text organization;
    std::vector<std::int64_t> notice_numbers;
};
struct user_notice
{
    std::optional<notice_reference> notice_ref;
    std::optional<display_text> explicit_text;
};
template<typename RangeType>
using certificate_policies = std::vector<policy_information<RangeType>>;

constexpr auto id_ce_policy_mappings = id_ce<33>;
using cert_policy_id = object_identifier_type;
struct policy_mapping
{
    cert_policy_id issuer_domain_policy;
    cert_policy_id subject_domain_policy;
};
using policy_mappings = std::vector<policy_mapping>;

constexpr auto id_ce_subject_alt_name = id_ce<17>;
template<typename RangeType>
using subject_alt_name = general_names<RangeType>;

constexpr auto id_ce_issuer_alt_name = id_ce<18>;
template<typename RangeType>
using issuer_alt_name = general_names<RangeType>;

constexpr auto id_ce_basic_constraints = id_ce<19>;
struct basic_constraints
{
    bool ca;
    std::optional<std::int64_t> path_len_constraint;
};

constexpr auto id_ce_name_constraints = id_ce<30>;
template<typename RangeType>
struct general_subtree
{
    general_name<RangeType> base;
    std::int64_t minimum;
    std::optional<std::int64_t> maximum;
};

template<typename BypeType>
using general_subtrees = std::vector<general_subtree<BypeType>>;

template<typename BypeType>
struct name_constraints
{
    std::optional<general_subtrees<BypeType>> permitted_subtrees;
    std::optional<general_subtrees<BypeType>> excluded_subtrees;
};

constexpr auto id_ce_policy_constraints = id_ce<36>;
using skip_certs = std::int64_t;
struct policy_constraints
{
    std::optional<skip_certs> require_explicit_policy;
    std::optional<skip_certs> inhibit_policy_mapping;
};

constexpr auto id_ce_crl_distribution_points = id_ce<31>;
template<typename RangeType>
using relative_distinguished_name = std::vector<attribute_value_assertion<RangeType>>;
template<typename RangeType>
using distribution_point_name = std::variant<
    general_names<RangeType>, //full_name
    relative_distinguished_name<RangeType>
>;
template<typename RangeType>
using reason_flags = bit_string<RangeType>;
struct reason_flags_values
{
    enum value
    {
        key_compromise = 1,
        ca_compromise = 2,
        affiliation_changed = 3,
        superseded = 4,
        cessation_of_operation = 5,
        certificate_hold = 6,
        privilege_withdrawn = 7,
        aa_compromise = 8
    };
};
template<typename RangeType>
struct distribution_point
{
    std::optional<distribution_point_name<RangeType>> distr_point;
    std::optional<reason_flags<RangeType>> reasons;
    std::optional<general_names<RangeType>> clr_issuer;
};
template<typename RangeType>
using crl_distribution_points = std::vector<distribution_point<RangeType>>;

constexpr auto id_ce_ext_key_usage = id_ce<37>;
constexpr auto any_extended_key_usage = id_ce<37, 0>;
template<std::uint32_t... Components>
constexpr auto id_kp = id_pkix<3, Components...>;
constexpr auto id_kp_server_auth = id_kp<1>;
constexpr auto id_kp_client_auth = id_kp<2>;
constexpr auto id_kp_code_signing = id_kp<3>;
constexpr auto id_kp_email_protection = id_kp<4>;
constexpr auto id_kp_ipsec_end_system = id_kp<5>; //Reserved and Obsolete
constexpr auto id_kp_ipsec_tunnel = id_kp<6>; //Reserved and Obsolete
constexpr auto id_kp_ipsec_user = id_kp<7>; //Reserved and Obsolete
constexpr auto id_kp_time_stamping = id_kp<8>;
constexpr auto id_kp_ocsp_signing = id_kp<9>;
constexpr auto id_kp_ocsp_basic = id_kp<9, 1>;
constexpr auto id_kp_ocsp_nonce = id_kp<9, 2>;
constexpr auto id_kp_ocsp_crl = id_kp<9, 3>;
constexpr auto id_kp_ocsp_response = id_kp<9, 4>;
constexpr auto id_kp_ocsp_nocheck = id_kp<9, 5>;
constexpr auto id_kp_ocsp_archive_cutoff = id_kp<9, 6>;
constexpr auto id_kp_ocsp_service_locator = id_kp<9, 7>;
constexpr auto id_kp_dvcs_data_validation_and_certification_server = id_kp<10>;
constexpr auto id_kp_sbgp_cert_aa_server_auth = id_kp<11>; //Reserved and Obsolete
constexpr auto id_kp_scvp_responder = id_kp<12>; //Reserved and Obsolete
constexpr auto id_kp_eap_over_ppp = id_kp<13>;
constexpr auto id_kp_eap_over_lan = id_kp<14>;
constexpr auto id_kp_scvp_server = id_kp<15>;
constexpr auto id_kp_scvp_client = id_kp<16>;
constexpr auto id_kp_ipsec_ike = id_kp<17>;
constexpr auto id_kp_capwap_ac = id_kp<18>;
constexpr auto id_kp_capwap_wtp = id_kp<19>;
constexpr auto id_kp_sip_domain = id_kp<20>;
constexpr auto id_kp_secure_shell_client = id_kp<21>;
constexpr auto id_kp_secure_shell_server = id_kp<22>;
constexpr auto id_kp_send_router = id_kp<23>;
constexpr auto id_kp_send_proxied_router = id_kp<24>;
constexpr auto id_kp_send_owner = id_kp<25>;
constexpr auto id_kp_send_proxied_owner = id_kp<26>;
constexpr auto id_kp_cmc_ca = id_kp<27>;
constexpr auto id_kp_cmc_ra = id_kp<28>;
constexpr auto id_kp_cmc_archive = id_kp<29>;
constexpr auto id_kp_bgpsec_router = id_kp<30>;
constexpr auto id_kp_brand_indicator_for_message_identification = id_kp<31>;
constexpr auto id_kp_cm_kga = id_kp<32>;
constexpr auto id_kp_rpc_tls_client = id_kp<33>;
constexpr auto id_kp_rpc_tls_server = id_kp<34>;
constexpr auto id_kp_bundle_security = id_kp<35>;
constexpr auto id_kp_document_signing = id_kp<36>;

using key_purpose_id = object_identifier_type;
using ext_key_usage_syntax = std::vector<key_purpose_id>;

constexpr auto id_ce_inhibit_any_policy = id_ce<54>;
using inhibit_any_policy = skip_certs;

constexpr auto id_ce_freshest_crl = id_ce<46>;
template<typename RangeType>
using freshest_crl = crl_distribution_points<RangeType>;

constexpr auto id_pe_authority_info_access = id_pe<1>;
template<typename RangeType>
struct access_description
{
    object_identifier_type access_method;
    general_name<RangeType> access_location;
};
template<typename RangeType>
using authority_info_access_syntax = std::vector<access_description<RangeType>>;

//access methods
constexpr auto id_ad_ocsp = id_ad<1>;
constexpr auto id_ad_ca_issuers = id_ad<2>;
constexpr auto id_ad_timestamping = id_ad<3>;
constexpr auto id_ad_ca_repository = id_ad<5>;

constexpr auto id_pe_subject_info_access = id_pe<11>;
template<typename RangeType>
using subject_info_access_syntax = std::vector<access_description<RangeType>>;

constexpr auto id_ce_crl_number = id_ce<20>;
using crl_number = std::int64_t;

constexpr auto id_ce_issuing_distribution_point = id_ce<28>;
template<typename RangeType>
struct issuing_distribution_point
{
    std::optional<distribution_point_name<RangeType>> distr_point;
    bool only_contains_user_certs;
    bool only_contains_ca_certs;
    std::optional<reason_flags<RangeType>> only_some_reasons;
    bool indirect_crl;
    bool only_contains_attribute_certs;
};

constexpr auto id_ce_delta_crl_indicator = id_ce<27>;
using base_crl_number = crl_number;

constexpr auto id_ce_crl_reasons = id_ce<21>;
enum class crl_reason
{
    unspecified = 0,
    key_compromise = 1,
    ca_compromise = 2,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    certificate_hold = 6,
    remove_from_crl = 8,
    privilege_withdrawn = 9,
    ac_compromise = 10
};

constexpr auto id_ce_certificate_issuer = id_ce<29>;
template<typename RangeType>
using certificate_issuer = general_names<RangeType>;

constexpr auto id_ce_hold_instruction_code = id_ce<23>;
using hold_instruction_code = object_identifier_type;
template<std::uint32_t... Components>
constexpr auto hold_instruction = std::to_array<std::uint32_t>({ 2, 2, 840, 10040, 2, Components... });
constexpr auto hold_instruction_none = hold_instruction<1>;
constexpr auto hold_instruction_call_issuer = hold_instruction<2>;
constexpr auto hold_instruction_reject = hold_instruction<3>;

constexpr auto id_ce_invalidity_date = id_ce<24>;
using invalidity_date = generalized_time;

constexpr auto id_sct_precert_signed_certificate_timestamp_list
    = std::to_array<std::uint32_t>({ 1, 3, 6, 1, 4, 1, 11129, 2, 4, 2 });
constexpr auto id_sct_cert_signed_certificate_timestamp_list
= std::to_array<std::uint32_t>({ 1, 3, 6, 1, 4, 1, 11129, 2, 4, 5 });
template<typename RangeType>
using signed_certificate_timestamp_list = RangeType;
} //namespace asn1::crypto::x509::ext
