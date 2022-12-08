#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "simple_asn1/types.h"

namespace asn1::crypto
{
using object_identifier_type = decoded_object_identifier<std::vector<std::uint32_t>>;

template<typename RangeType>
struct algorithm_identifier
{
	object_identifier_type algorithm;
	std::optional<RangeType> parameters;
};

template<typename RangeType>
struct attribute_value_assertion
{
	object_identifier_type attribute_type;
	RangeType attribute_value;
};

template<typename RangeType>
using relative_distinguished_name_type = std::vector<attribute_value_assertion<RangeType>>;
template<typename RangeType>
using name_type = std::vector<relative_distinguished_name_type<RangeType>>;

using time_type = std::variant<utc_time, generalized_time>;

template<std::uint32_t... Components>
constexpr auto id_pkcs1 = std::to_array<std::uint32_t>({ 1, 2, 840, 113549, 1, 1, Components... });
template<std::uint32_t... Components>
constexpr auto id_pkix = std::to_array<std::uint32_t>({ 1, 3, 6, 1, 5, 5, 7, Components... });

using country_name = std::variant<
	std::string, //x121-dcc-code
	std::string //iso-3166-alpha2-code
>;

using administration_domain_name = std::variant<
	std::string, //numeric
	std::string //printable
>;

using x121_address = std::string;
using network_address = x121_address;
using terminal_identifier = std::string;

using private_domain_name = std::variant<
	std::string, //numeric
	std::string //printable
>;

using organization_name = std::string;
using numeric_user_identifier = std::string;

struct personal_name
{
	std::string surname;
	std::optional<std::string> given_name;
	std::optional<std::string> initials;
	std::optional<std::string> generation_qualifier;
};

using organizational_unit_names = std::vector<std::string>;

struct build_in_standard_attributes
{
	std::optional<country_name> country;
	std::optional<administration_domain_name> administration_domain;
	std::optional<network_address> network_addr;
	std::optional<terminal_identifier> terminal;
	std::optional<private_domain_name> private_domain;
	std::optional<organization_name> organization;
	std::optional<numeric_user_identifier> numeric_user;
	std::optional<personal_name> personal;
	std::optional<organizational_unit_names> organizational_unit;
};

struct built_in_domain_defined_attribute
{
	std::string type;
	std::string value;
};

using build_in_domain_defined_attributes = std::vector<built_in_domain_defined_attribute>;

template<typename RangeType>
struct extension_attribute
{
	std::int32_t extension_attribute_type; //extension_attribute_value
	RangeType extention_attribute_value;
};

template<typename RangeType>
using extension_attributes = std::vector<extension_attribute<RangeType>>;

enum class extension_attribute_value : std::int32_t
{
	common_name = 1,
	teletex_common_name = 2,
	teletex_organization_name = 3,
	teletex_personal_name = 4,
	teletex_organizational_unit_names = 5,
	pds_name = 7,
	physical_delivery_country_name = 8,
	postal_code = 9,
	physical_delivery_office_name = 10,
	physical_delivery_office_number = 11,
	extension_or_address_components = 12,
	physical_delivery_personal_name = 13,
	physical_delivery_organization_name = 14,
	extension_physical_delivery_address_components = 15,
	unformatted_postal_address = 16,
	street_address = 17,
	post_office_box_address = 18,
	poste_restante_address = 19,
	unique_postal_name = 20,
	local_postal_attributes = 21,
	extended_network_address = 22,
	terminal_type = 23,
	teletex_domain_defined_attributes = 6
}; //namespace ext

namespace ext
{
using common_name = std::string;
using teletex_common_name = std::string;
using teletex_organization_name = std::string;

struct teletex_personal_name
{
	std::string surname;
	std::optional<std::string> given_name;
	std::optional<std::string> initials;
	std::optional<std::string> generation_qualofoer;
};

using teletex_organizational_unit_name = std::string;
using teletex_organizational_unit_names = std::vector<teletex_organizational_unit_name>;
using pds_name = std::string;
using physical_delivery_country_name = std::variant<
	std::string, //x121-dcc-code
	std::string //iso-3166-alpha2-code
>;
using postal_code = std::variant<
	std::string, //numeric-code
	std::string //printable-code
>;

struct pds_parameter
{
	std::optional<std::string> printable_string;
	std::optional<std::string> teletex_string;
};

using physical_delivery_office_name = pds_parameter;
using physical_delivery_office_number = pds_parameter;
using extension_or_address_components = pds_parameter;
using physical_delivery_personal_name = pds_parameter;
using physical_delivery_organization_name = pds_parameter;
using extension_physical_delivery_address_components = pds_parameter;

struct unformatted_postal_address
{
	std::optional<std::vector<std::string>> printable_address;
	std::optional<std::string> teletex_string;
};

using street_address = pds_parameter;
using post_office_box_address = pds_parameter;
using poste_restante_address = pds_parameter;
using unique_postal_name = pds_parameter;
using local_postal_attributes = pds_parameter;

struct e163_4_adress
{
	std::string number;
	std::optional<std::string> sub_address;
};

template<typename RangeType>
struct presentation_address
{
	std::optional<RangeType> p_selector;
	std::optional<RangeType> s_selector;
	std::optional<RangeType> t_selector;
	std::vector<RangeType> n_addresses;
};

template<typename RangeType>
using extended_network_address = std::variant<
	e163_4_adress,
	presentation_address<RangeType>
>;

using terminal_type = std::int32_t; //terminal_type_value

enum class terminal_type_value
{
	telex = 3,
	teletex = 4,
	g3_facsimile = 5,
	g4_facsimile = 6,
	ia5_terminal = 7,
	videotex = 8
};

struct teletex_domain_defined_attribute
{
	std::string type;
	std::string value;
};

using teletex_domain_defined_attributes = std::vector<teletex_domain_defined_attribute>;
} //namespace ext

template<typename RangeType>
struct or_address
{
	build_in_standard_attributes standard_attributes;
	std::optional<build_in_domain_defined_attributes> domain_defined_attributes;
	std::optional<extension_attributes<RangeType>> ext_attributes;
};

using directory_string = std::variant<
	std::string, //teletex_string
	std::string, //printable_string
	std::u32string, //universal_string
	std::string, //utf8_string
	std::u16string //bmp_string
>;
} //namespace asn1::crypto
