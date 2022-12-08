#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>

#include "simple_asn1/crypto/crypto_common_types.h"
#include "simple_asn1/types.h"

namespace asn1::crypto::x520
{
using name = directory_string;
using common_name = directory_string;
using locality_name = directory_string;
using state_or_province_name = directory_string;
using organization_name = directory_string;
using organizational_unit_name = directory_string;
using title = directory_string;
using pseudonim = directory_string;
using dn_qualifier = std::string;
using country_name = std::string;
using serial_number = std::string;
using domain_component = std::string;
using email_address = std::string;

template<std::uint32_t... Components>
constexpr auto id_at = std::to_array<std::uint32_t>({ 2, 5, 4, Components... });

//name
constexpr auto id_at_name = id_at<41>;
constexpr auto id_at_surname = id_at<4>;
constexpr auto id_at_given_name = id_at<42>;
constexpr auto id_at_initials = id_at<43>;
constexpr auto id_at_generation_qualifier = id_at<44>;

//common_name
constexpr auto id_at_common_name = id_at<3>;

//locality_name
constexpr auto id_at_locality_name = id_at<7>;

//state_or_province_name
constexpr auto id_at_state_or_province_name = id_at<8>;

//organization_name
constexpr auto id_at_organization_name = id_at<10>;

//organizational_unit_name
constexpr auto id_at_organizational_unit_name = id_at<11>;

//title
constexpr auto id_at_title = id_at<12>;

//dn_qualifier
constexpr auto id_at_dn_qualifier = id_at<46>;

//country_name
constexpr auto id_at_country_name = id_at<6>;

//serial_number
constexpr auto id_at_serial_number = id_at<5>;

//pseudonim
constexpr auto id_at_pseudonim = id_at<65>;

//domain_component
constexpr auto id_domain_component = std::to_array<std::uint32_t>(
	{ 0, 9, 2342, 19200300, 100, 1, 25 });

//email_address
constexpr auto id_email_address = std::to_array<std::uint32_t>(
	{ 1, 2, 840, 113549, 1, 9, 1 });
} //namespace asn1::crypto::x520
