// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/spec.h"

namespace asn1::spec::crypto
{
template<detail::compile_time_string Name>
using algorithm_identifier = sequence_with_options<opts::named<Name>,
	object_identifier<opts::named<"algorithm">>,
	optional<any<opts::named<"parameters">>>
>;

using attribute_value_assertion = sequence_with_options<
	opts::named<"AttributeValueAssertion">,
	object_identifier<opts::named<"attributeType">>,
	any<opts::named<"attributeValue">>
>;

using relative_distinguished_name = set_of_with_options<
	opts::named<"RelativeDistinguishedName">,
	attribute_value_assertion
>;

template<detail::compile_time_string Name>
using name = sequence_of_with_options<opts::named<Name>, relative_distinguished_name>;

template<detail::compile_time_string Name>
using time = choice_with_options<opts::named<Name>,
	utc_time<opts::options<opts::zero_year<2000u>, opts::name<Name>>>,
	generalized_time<opts::options<opts::name<Name>>>
>;

template<detail::compile_time_string Name>
using directory_string = choice_with_options<
	opts::named<"DirectoryString">,
	teletex_string<opts::named<"teletexString">>,
	printable_string<opts::named<"printableString">>,
	universal_string<opts::named<"universalString">>,
	utf8_string<opts::named<"utf8String">>,
	bmp_string<opts::named<"bmpString">>
>;

template<detail::compile_time_string Name>
using directory_name = directory_string<Name>;

using country_name = tagged_with_options<1u, encoding::expl, cls::application,
	opts::named<"CountryName">,
	choice_with_options<opts::named<"CountryName">,
		numeric_string<opts::named<"x121-dcc-code">>,
		printable_string<opts::named<"iso-3166-alpha2-code">>
	>
>;

using administration_domain_name = tagged_with_options<2u, encoding::expl, cls::application,
	opts::named<"AdministrationDomainName">,
	choice_with_options<opts::named<"AdministrationDomainName">,
		numeric_string<opts::named<"numeric">>,
		printable_string<opts::named<"printable">>
	>
>;

using network_address = numeric_string<opts::named<"NetworkAddress">>;

using terminal_identifier = printable_string<opts::named<"TerminalIdentifier">>;

using private_domain_name = choice_with_options<opts::named<"PrivateDomainName">,
	numeric_string<opts::named<"numeric">>,
	printable_string<opts::named<"printable">>
>;

using organization_name = printable_string<opts::named<"OrganizationName">>;

using numeric_user_identifier = numeric_string<opts::named<"NumericUserIdentifier">>;

using personal_name = set_with_options<opts::named<"PersonalName">,
	tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"surname">,
		printable_string<opts::named<"surname">>
	>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"given-name">,
		printable_string<opts::named<"given-name">>
	>>,
	optional<tagged_with_options<2u, encoding::impl, cls::context_specific,
		opts::named<"initials">,
		printable_string<opts::named<"initials">>
	>>,
	optional<tagged_with_options<3u, encoding::impl, cls::context_specific,
		opts::named<"generation-qualifier">,
		printable_string<opts::named<"generation-qualifier">>
	>>
>;

using organizational_unit_name = printable_string<opts::named<"OrganizationalUnitName">>;

using organizational_unit_names = sequence_of_with_options<
	opts::named<"OrganizationalUnitNames">,
	organizational_unit_name
>;

using built_in_standard_attributes = sequence_with_options<
	opts::named<"BuiltInStandardAttributes">,
	optional<country_name>,
	optional<administration_domain_name>,
	optional<tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"network-address">,
		network_address
	>>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"terminal-identifier">,
		terminal_identifier
	>>,
	optional<tagged_with_options<2u, encoding::expl, cls::context_specific,
		opts::named<"private-domain-name">,
		private_domain_name
	>>,
	optional<tagged_with_options<3u, encoding::impl, cls::context_specific,
		opts::named<"organization-name">,
		organization_name
	>>,
	optional<tagged_with_options<4u, encoding::impl, cls::context_specific,
		opts::named<"numeric-user-identifier">,
		numeric_user_identifier
	>>,
	optional<tagged_with_options<5u, encoding::impl, cls::context_specific,
		opts::named<"personal-name">,
		personal_name
	>>,
	optional<tagged_with_options<6u, encoding::impl, cls::context_specific,
		opts::named<"organizational-unit-names">,
		organizational_unit_names
	>>
>;

using built_in_domain_defined_attribute = sequence_with_options<
	opts::named<"BuiltInDomainDefinedAttribute">,
	printable_string<opts::named<"type">>,
	printable_string<opts::named<"value">>
>;

using built_in_domain_defined_attributes = sequence_of_with_options<
	opts::named<"BuiltInDomainDefinedAttributes">,
	built_in_domain_defined_attribute
>;

using extension_attribute = sequence_with_options<
	opts::named<"ExtensionAttribute">,
	tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"extension-attribute-type">,
		integer<opts::named<"extension-attribute-type">>
	>,
	tagged_with_options<1u, encoding::expl, cls::context_specific,
		opts::named<"extension-attribute-value">,
		any<opts::named<"extension-attribute-value">>
	>
>;

using extension_attributes = set_of_with_options<
	opts::named<"ExtensionAttributes">,
	extension_attribute
>;

using or_address = sequence_with_options<
	opts::named<"ORAddress">,
	built_in_standard_attributes,
	optional<built_in_domain_defined_attributes>,
	optional<extension_attributes>
>;

namespace ext
{
//extension_attributes: 1
using common_name = printable_string<opts::named<"CommonName">>;

//extension_attributes: 2
using teletex_common_name = teletex_string<opts::named<"TeletexCommonName">>;

//extension_attributes: 3
using teletex_organization_name = teletex_string<opts::named<"TeletexOrganizationName">>;

//extension_attributes: 4
using teletex_personal_name = set_with_options<
	opts::named<"TeletexPersonalName">,
	tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"surname">,
		teletex_string<opts::named<"surname">>
	>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"given-name">,
		teletex_string<opts::named<"given-name">>
	>>,
	optional<tagged_with_options<2u, encoding::impl, cls::context_specific,
		opts::named<"initials">,
		teletex_string<opts::named<"initials">>
	>>,
	optional<tagged_with_options<3u, encoding::impl, cls::context_specific,
		opts::named<"generation-qualifier">,
		teletex_string<opts::named<"generation-qualifier">>
	>>
>;

//extension_attributes: 5
using teletex_organizational_unit_name = teletex_string<
	opts::named<"TeletexOrganizationalUnitName">>;
using teletex_organizational_unit_names = sequence_of_with_options<
	opts::named<"TeletexOrganizationalUnitNames">,
	teletex_organizational_unit_name
>;

//extension_attributes: 7
using pds_name = printable_string<opts::named<"PDSName">>;

//extension_attributes: 8
using physical_delivery_country_name = choice_with_options<
	opts::named<"PhysicalDeliveryCountryName">,
	numeric_string<opts::named<"x121-dcc-code">>,
	printable_string<opts::named<"iso-3166-alpha2-code">>
>;

//extension_attributes: 9
using postal_code = choice_with_options<
	opts::named<"PostalCode">,
	numeric_string<opts::named<"numeric-code">>,
	printable_string<opts::named<"printable-code">>
>;

//extension_attributes: 10
template<detail::compile_time_string Name>
using pds_parameter = set_with_options<
	opts::named<Name>,
	printable_string<opts::named<"printable-string">>,
	teletex_string<opts::named<"teletex-string">>
>;

using physical_delivery_office_name = pds_parameter<"PhysicalDeliveryOfficeName">;

//extension_attributes: 11
using physical_delivery_office_number = pds_parameter<"PhysicalDeliveryOfficeNumber">;

//extension_attributes: 12
using extension_or_address_components = pds_parameter<"ExtensionORAddressComponents">;

//extension_attributes: 13
using physical_delivery_personal_name = pds_parameter<"PhysicalDeliveryPersonalName">;

//extension_attributes: 14
using physical_delivery_organization_name = pds_parameter<"PhysicalDeliveryOrganizationName">;

//extension_attributes: 15
using extension_physical_delivery_address_components
	= pds_parameter<"ExtensionPhysicalDeliveryAddressComponents">;

//extension_attributes: 16
using unformatted_postal_address = set_with_options<
	opts::named<"UnformattedPostalAddress">,
	optional<sequence_of_with_options<
		opts::named<"printable-address">,
		printable_string<opts::named<"printable-address">>
	>>,
	optional<teletex_string<opts::named<"teletex-string">>>
>;

//extension_attributes: 17
using street_address = pds_parameter<"StreetAddress">;

//extension_attributes: 18
using post_office_box_address = pds_parameter<"PostOfficeBoxAddress">;

//extension_attributes: 19
using poste_restante_address = pds_parameter<"PosteRestanteAddress">;

//extension_attributes: 20
using unique_postal_name = pds_parameter<"UniquePostalName">;

//extension_attributes: 21
using local_postal_attributes = pds_parameter<"LocalPostalAttributes">;

//extension_attributes: 22
using presentation_address = sequence_with_options<
	opts::named<"PresentationAddress">,
	tagged_with_options<0u, encoding::expl, cls::context_specific,
		opts::named<"pSelector">,
		optional<octet_string<opts::named<"pSelector">>>
	>,
	tagged_with_options<1u, encoding::expl, cls::context_specific,
		opts::named<"sSelector">,
		optional<octet_string<opts::named<"sSelector">>>
	>,
	tagged_with_options<2u, encoding::expl, cls::context_specific,
		opts::named<"tSelector">,
		optional<octet_string<opts::named<"tSelector">>>
	>,
	tagged_with_options<3u, encoding::expl, cls::context_specific,
		opts::named<"nAddresses">,
		set_of_with_options<
			opts::named<"nAddresses">,
			octet_string<opts::named<"nAddresses">>
		>
	>
>;

using extended_network_address = choice_with_options<
	opts::named<"ExtendedNetworkAddress">,
	sequence_with_options<
		opts::named<"e163-4-address">,
		tagged_with_options<0u, encoding::impl, cls::context_specific,
			opts::named<"number">,
			numeric_string<opts::named<"number">>
		>,
		optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
			opts::named<"sub-address">,
			numeric_string<opts::named<"sub-address">>
		>>
	>,
	tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"psap-address">,
		presentation_address
	>
>;

//extension_attributes: 23
using terminal_type = integer<opts::named<"TerminalType">>;

//extension_attributes: 6
using teletex_domain_defined_attribute = sequence_with_options<
	opts::named<"TeletexDomainDefinedAttribute">,
	teletex_string<opts::named<"type">>,
	teletex_string<opts::named<"value">>
>;

using teletex_domain_defined_attributes = sequence_of_with_options<
	opts::named<"TeletexDomainDefinedAttributes">,
	teletex_domain_defined_attribute
>;
} //namespace ext
} //namespace asn1::spec::crypto
