// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/crypto/x509/spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::pkcs7::authenticode
{
using digest_algorithm_identifier = algorithm_identifier<"digestAlgorithm">;

using digest_algorithm_identifiers = set_of_with_options<opts::named<"daSet">,
	digest_algorithm_identifier
>;

using spc_pe_image_flags = bit_string<opts::named<"SpcPeImageFlags">>;

using spc_serialized_object = sequence_with_options<
	opts::named<"SpcSerializedObject">,
	octet_string<opts::named<"classId">>,
	octet_string<opts::named<"serializedData">>
>;

using spc_string = choice_with_options<opts::named<"SpcString">,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"unicode">,
		bmp_string<opts::named<"unicode">>
	>,
	tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"ascii">,
		ia5_string<opts::named<"ascii">>
	>
>;

using spc_link = choice_with_options<opts::named<"SpcLink">,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"url">,
		ia5_string<opts::named<"url">>
	>,
	tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"moniker">,
		spc_serialized_object
	>,
	tagged_with_options<2, encoding::expl, cls::context_specific,
		opts::named<"file">,
		spc_string
	>
>;

using spc_pe_image_data = sequence_with_options<
	opts::named<"SpcPeImageData">,
	spec::optional<spc_pe_image_flags>,
	spec::optional<tagged_with_options<0, encoding::expl, cls::context_specific,
		opts::named<"file">,
		spc_link
	>>
>;

using spc_attribute_type_and_optional_value = sequence_with_options<
	opts::named<"SpcAttributeTypeAndOptionalValue">,
	object_identifier<opts::named<"type">>,
	spc_pe_image_data
>;

using digest_info = sequence_with_options<
	opts::named<"DigestInfo">,
	algorithm_identifier<"digestAlgorithm">,
	octet_string<opts::named<"digest">>
>;

using spc_indirect_data_content = sequence_with_options<
	opts::named<"SpcIndirectDataContent">,
	spc_attribute_type_and_optional_value,
	digest_info
>;

using encap_content_info = sequence_with_options<
	opts::named<"encapsulatedContentInfo">,
	object_identifier<opts::named<"contentType">>,
	tagged_with_options<0, encoding::expl, cls::context_specific,
		opts::named<"content">,
		spc_indirect_data_content
	>
>;

using certificate = x509::certificate_base<"certificate">;
using extended_certificate = x509::certificate_base<"extendedCertificate">;

using certificate_choices = choice_with_options<
	opts::named<"ExtendedCertificateOrCertificate">,
	certificate,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"extendedCertificate">,
		extended_certificate
	>
>;

using extended_certificates_and_certificates = set_of_with_options<opts::named<"certSet">,
	certificate_choices
>;

using issuer_and_serial_number = sequence_with_options<
	opts::named<"IssuerAndSerialNumber">,
	name<"issuer">,
	integer<opts::named<"serialNumber">>
>;

template<detail::compile_time_string Name>
using attribute = sequence_with_options<opts::named<Name>,
	object_identifier<opts::named<"type">>,
	set_of_with_options<opts::named<"values">,
		any<opts::named<"values">>
	>
>;

using authenticated_attributes = set_of_with_options<
	opts::named<"authenticatedAttributes">,
	attribute<"AuthenticatedAttribute">
>;
using unauthenticated_attributes = set_of_with_options<
	opts::named<"unauthenticatedAttributes">,
	attribute<"UnauthenticatedAttribute">
>;

using encrypted_digest = octet_string<opts::named<"encryptedDigest">>;

using signer_info = sequence_with_options<opts::named<"SignerInfo">,
	//Only one info for authenticode
	integer<opts::named<"version">>,
	issuer_and_serial_number,
	digest_algorithm_identifier,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"authenticatedAttributes">,
		authenticated_attributes
	>>,
	algorithm_identifier<"digestEncryptionAlgorithm">,
	encrypted_digest,
	optional<tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"unauthenticatedAttributes">,
		unauthenticated_attributes
	>>
>;

using signer_infos = set_of_with_options<opts::named<"siSet">,
	signer_info
>;

using signed_data = sequence_with_options<opts::named<"SignedData">,
	integer<opts::named<"version">>,
	digest_algorithm_identifiers,
	encap_content_info,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"certificates">,
		extended_certificates_and_certificates
	>>,
	//optional<tagged_with_options<1, encoding::impl, cls::context_specific, opts::named<"crls">,
	//	certificate_revocation_lists //Not used in authenticode
	//>>,
	signer_infos
>;

using content_info = sequence_with_options<opts::named<"PKCS7ContentInfo">,
	object_identifier<opts::named<"contentType">>,
	tagged_with_options<0, encoding::expl, cls::context_specific,
		opts::named<"content">, signed_data>
>;

} //namespace asn1::spec::crypto::pkcs7::authenticode
