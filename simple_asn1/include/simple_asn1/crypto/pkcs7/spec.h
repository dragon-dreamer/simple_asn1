// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/crypto/x509/spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::pkcs7
{
using digest_algorithm_identifier = algorithm_identifier<"digestAlgorithm">;

using digest_algorithm_identifiers = set_of_with_options<opts::named<"daSet">,
	digest_algorithm_identifier
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

template<typename ContentInfo>
using signed_data = sequence_with_options<opts::named<"SignedData">,
	integer<opts::named<"version">>,
	digest_algorithm_identifiers,
	ContentInfo,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"certificates">,
		extended_certificates_and_certificates
	>>,
	//optional<tagged_with_options<1, encoding::impl, cls::context_specific, opts::named<"crls">,
	//	certificate_revocation_lists //Not implemented
	//>>,
	signer_infos
>;

template<typename ContentInfo>
using content_info_base = sequence_with_options<opts::named<"PKCS7ContentInfo">,
	object_identifier<opts::named<"contentType">>,
	tagged_with_options<0, encoding::expl, cls::context_specific,
		opts::named<"content">, signed_data<ContentInfo>>
>;

} //namespace asn1::spec::crypto::pkcs7
