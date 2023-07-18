// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::x509::ext
{
using key_identifier = octet_string<opts::named<"KeyIdentifier">>;
using certificate_serial_number = integer<opts::named<"CertificateSerialNumber">>;

using another_name = sequence_with_options<
	opts::named<"AnotherName">,
	object_identifier<opts::named<"type-id">>,
	tagged_with_options<0u, encoding::expl, cls::context_specific,
		opts::named<"value">,
		any<opts::named<"value">>
	>
>;

using edi_party_name = sequence_with_options<
	opts::named<"EDIPartyName">,
	optional<tagged_with_options<0u, encoding::expl, cls::context_specific,
		opts::named<"nameAssigner">,
		directory_string<"nameAssigner">
	>>,
	tagged_with_options<1u, encoding::expl, cls::context_specific,
		opts::named<"partyName">,
		directory_string<"partyName">
	>
>;

template<detail::compile_time_string Name>
using general_name = choice_with_options<
	opts::named<Name>,
	tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"otherName">,
		another_name
	>,
	tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"rfc822Name">,
		ia5_string<opts::named<"rfc822Name">>
	>,
	tagged_with_options<2u, encoding::impl, cls::context_specific,
		opts::named<"dNSName">,
		ia5_string<opts::named<"dNSName">>
	>,
	tagged_with_options<3u, encoding::impl, cls::context_specific,
		opts::named<"x400Address">,
		or_address
	>,
	tagged_with_options<4u, encoding::expl, cls::context_specific,
		opts::named<"directoryName">,
		name<"directoryName">
	>,
	tagged_with_options<5u, encoding::impl, cls::context_specific,
		opts::named<"ediPartyName">,
		edi_party_name
	>,
	tagged_with_options<6u, encoding::impl, cls::context_specific,
		opts::named<"uniformResourceIdentifier">,
		ia5_string<opts::named<"uniformResourceIdentifier">>
	>,
	tagged_with_options<7u, encoding::impl, cls::context_specific,
		opts::named<"iPAddress">,
		octet_string<opts::named<"iPAddress">>
	>,
	tagged_with_options<8u, encoding::impl, cls::context_specific,
		opts::named<"registeredID">,
		object_identifier<opts::named<"registeredID">>
	>
>;

template<detail::compile_time_string Name>
using general_names = sequence_of_with_options<
	opts::named<Name>,
	general_name<Name>
>;

//id-ce 35
using authority_key_identifier = sequence_with_options<
	opts::named<"AuthorityKeyIdentifier">,
	optional<tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"keyIdentifier">,
		key_identifier
	>>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"authorityCertIssuer">,
		general_names<"authorityCertIssuer">
	>>,
	optional<tagged_with_options<2u, encoding::impl, cls::context_specific,
		opts::named<"authorityCertSerialNumber">,
		certificate_serial_number
	>>
>;

//id-ce 14
using subject_key_identifier = octet_string<opts::named<"SubjectKeyIdentifier">>;

//id-ce 15
using key_usage = bit_string<opts::named<"KeyUsage">>;

//id-ce 16
using private_key_usage_period = sequence_with_options<
	opts::named<"PrivateKeyUsagePeriod">,
	optional<tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"notBefore">,
		generalized_time<opts::named<"notBefore">>
	>>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"notAfter">,
		generalized_time<opts::named<"notAfter">>
	>>
>;

//id-ce 32
template<detail::compile_time_string Name>
using cert_policy_id = object_identifier<opts::named<Name>>;

using policy_qualifier_id = object_identifier<opts::named<"PolicyQualifierId">>;

using policy_qualifier_info = sequence_with_options<
	opts::named<"PolicyQualifierInfo">,
	policy_qualifier_id,
	any<opts::named<"qualifier">>
>;

using policy_information = sequence_with_options<
	opts::named<"PolicyInformation">,
	cert_policy_id<"policyIdentifier">,
	optional<sequence_of_with_options<
		opts::named<"policyQualifiers">,
		policy_qualifier_info
	>>
>;

using certificate_policies = sequence_of_with_options<
	opts::named<"CertificatePolicies">,
	policy_information
>;

using cps_uri = ia5_string<opts::named<"CPSuri">>;

template<detail::compile_time_string Name>
using display_text = choice_with_options<
	opts::named<Name>,
	ia5_string<opts::named<"ia5String">>,
	visible_string<opts::named<"visibleString">>,
	bmp_string<opts::named<"bmpString">>,
	utf8_string<opts::named<"utf8String">>
>;

using notice_reference = sequence_with_options<
	opts::named<"NoticeReference">,
	display_text<"organization">,
	sequence_of_with_options<
		opts::named<"noticeNumbers">,
		integer<opts::named<"noticeNumbers">>
	>
>;

using user_notice = sequence_with_options<
	opts::named<"UserNotice">,
	optional<notice_reference>,
	optional<display_text<"explicitText">>
>;

//id-ce 33
using policy_mappings = sequence_of_with_options<
	opts::named<"PolicyMappings">,
	sequence_with_options<
		opts::named<"PolicyMapping">,
		cert_policy_id<"issuerDomainPolicy">,
		cert_policy_id<"subjectDomainPolicy">
	>
>;

//id-ce 17
using subject_alt_name = general_names<"SubjectAltName">;

//id-ce 18
using issuer_alt_name = general_names<"IssuerAltName">;

//id-ce 19
using basic_constraints = sequence_with_options<
	opts::named<"BasicConstraints">,
	optional_default<default_value<false>, boolean<opts::named<"cA">>>,
	optional<integer<opts::named<"pathLenConstraint">>>
>;

//id-ce 30
template<detail::compile_time_string Name>
using base_distance = integer<opts::named<Name>>;

using general_subtree = sequence_with_options<
	opts::named<"GeneralSubtree">,
	general_name<"base">,
	optional_default<default_value<0>,
		tagged_with_options<0u, encoding::impl, cls::context_specific,
			opts::named<"minimum">,
			base_distance<"minimum">
		>
	>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"maximum">,
		base_distance<"maximum">
	>>
>;

using general_subtrees = sequence_of_with_options<
	opts::named<"GeneralSubtrees">,
	general_subtree
>;

using name_constraints = sequence_with_options<
	opts::named<"NameConstraints">,
	optional<tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"permittedSubtrees">,
		general_subtrees
	>>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"excludedSubtrees">,
		general_subtrees
	>>
>;

//id-ce 36
template<detail::compile_time_string Name>
using skip_certs = integer<opts::named<Name>>;

using policy_constraints = sequence_with_options<
	opts::named<"PolicyConstraints">,
	optional<tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"requireExplicitPolicy">,
		skip_certs<"requireExplicitPolicy">
	>>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"inhibitPolicyMapping">,
		skip_certs<"inhibitPolicyMapping">
	>>
>;

//id-ce 31
using distribution_point_name = choice_with_options<
	opts::named<"">,
	tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"fullName">,
		general_names<"fullName">
	>,
	tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"fullName">,
		relative_distinguished_name
	>
>;

using reason_flags = bit_string<opts::named<"ReasonFlags">>;

using distribution_point = sequence_with_options<
	opts::named<"DistributionPoint">,
	optional<tagged_with_options<0u, encoding::expl, cls::context_specific,
		opts::named<"distributionPoint">,
		distribution_point_name
	>>,
	optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"reasons">,
		reason_flags
	>>,
	optional<tagged_with_options<2u, encoding::impl, cls::context_specific,
		opts::named<"cRLIssuer">,
		general_names<"cRLIssuer">
	>>
>;

using crl_distribution_points = sequence_of_with_options<
	opts::named<"CRLDistributionPoints">,
	distribution_point
>;

//id-ce 37
using key_purpose_id = object_identifier<opts::named<"KeyPurposeId">>;
using ext_key_usage_syntax = sequence_of_with_options<
	opts::named<"ExtKeyUsageSyntax">,
	key_purpose_id
>;

//id-ce 54
using inhibit_any_policy = skip_certs<"InhibitAnyPolicy">;

//id-ce 46
using freshest_crl = crl_distribution_points;

//id-pe 1
using access_description = sequence_with_options<
	opts::named<"AccessDescription">,
	object_identifier<opts::named<"accessMethod">>,
	general_name<"accessLocation">
>;

using authority_info_access_syntax = sequence_of_with_options<
	opts::named<"AuthorityInfoAccessSyntax">,
	access_description
>;

//id-pe 11
using subject_info_access_syntax = sequence_of_with_options<
	opts::named<"SubjectInfoAccessSyntax">,
	access_description
>;

//id-ce 20
using crl_number = integer<opts::named<"CRLNumber">>;

//id-ce 28
using issuing_distribution_point = sequence_with_options<
	opts::named<"IssuingDistributionPoint">,
	optional<tagged_with_options<0u, encoding::expl, cls::context_specific,
		opts::named<"distributionPoint">,
		distribution_point_name
	>>,
	optional_default<default_value<false>,
		tagged_with_options<1u, encoding::impl, cls::context_specific,
			opts::named<"onlyContainsUserCerts">,
			boolean<opts::named<"onlyContainsUserCerts">>
		>
	>,
	optional_default<default_value<false>,
		tagged_with_options<2u, encoding::impl, cls::context_specific,
			opts::named<"onlyContainsCACerts">,
			boolean<opts::named<"onlyContainsCACerts">>
		>
	>,
	optional<tagged_with_options<3u, encoding::impl, cls::context_specific,
		opts::named<"onlySomeReasons">,
		reason_flags
	>>,
	optional_default<default_value<false>,
		tagged_with_options<4u, encoding::impl, cls::context_specific,
			opts::named<"indirectCRL">,
			boolean<opts::named<"indirectCRL">>
		>
	>,
	optional_default<default_value<false>,
		tagged_with_options<5u, encoding::impl, cls::context_specific,
			opts::named<"onlyContainsAttributeCerts">,
			boolean<opts::named<"onlyContainsAttributeCerts">>
		>
	>
>;

//id-ce 27
using base_crl_number = integer<opts::named<"BaseCRLNumber">>;

//id-ce 21
using crl_reason = enumerated<opts::named<"CRLReason">>;

//id-ce 29
using certificate_issuer = general_names<"CertificateIssuer">;

//id-ce 23
using hold_instruction_code = object_identifier<opts::named<"HoldInstructionCode">>;

//id-ce 24
using invalidity_date = generalized_time<opts::named<"InvalidityDate">>;

//SCT 1.3.6.1.4.1.11129.2.4.2
using signed_certificate_timestamp_list = octet_string<
	opts::named<"SignedCertificateTimestampList">>;
} //namespace asn1::spec::crypto::x509::ext
