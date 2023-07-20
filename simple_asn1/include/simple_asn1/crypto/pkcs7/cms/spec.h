// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/crypto/pkcs7/spec.h"
#include "simple_asn1/crypto/x509/extensions_spec.h"
#include "simple_asn1/crypto/x509/spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::pkcs7::cms
{

using issuer_serial = sequence_with_options<
	opts::named<"IssuerSerial">,
	x509::ext::general_names<"issuer">,
	integer<opts::named<"serial">>,
	optional<bit_string<opts::named<"issuerUID">>>
>;

using attr_cert_validity_period = sequence_with_options<
	opts::named<"AttCertValidityPeriod">,
	generalized_time<opts::named<"notBeforeTime">>,
	generalized_time<opts::named<"notAfterTime">>
>;

using attribute_certificate_info_v1 = sequence_with_options<
	opts::named<"AttributeCertificateInfoV1">,
	optional_default<default_value<0>, integer<opts::named<"AttCertVersionV1">>>,
	choice_with_options<
		opts::named<"subject">,
		tagged_with_options<0, encoding::expl, cls::context_specific,
			opts::named<"baseCertificateID">,
			issuer_serial
		>,
		tagged_with_options<1, encoding::expl, cls::context_specific,
			opts::named<"subjectName">,
			x509::ext::general_names<"subjectName">
		>
	>,
	x509::ext::general_names<"issuer">,
	algorithm_identifier<"signature">,
	integer<opts::named<"serialNumber">>,
	attr_cert_validity_period,
	sequence_of_with_options<
		opts::named<"attributes">,
		attribute<"attribute">
	>,
	optional<bit_string<opts::named<"issuerUniqueID">>>,
	optional<x509::extensions>
>;

using attribute_certificate_v1 = sequence_with_options<
	opts::named<"AttributeCertificateV1">,
	attribute_certificate_info_v1,
	algorithm_identifier<"signatureAlgorithm">,
	bit_string<opts::named<"signature">>
>;

using object_digest_info = sequence_with_options<
	opts::named<"holder">,
	enumerated<opts::named<"digestedObjectType">>,
	optional<object_identifier<opts::named<"otherObjectTypeID">>>,
	algorithm_identifier<"digestAlgorithm">,
	bit_string<opts::named<"objectDigest">>
>;

using holder = sequence_with_options<
	opts::named<"holder">,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"baseCertificateID">,
		issuer_serial
	>>,
	optional<tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"entityName">,
		x509::ext::general_names<"entityName">
	>>,
	optional<tagged_with_options<2, encoding::impl, cls::context_specific,
		opts::named<"objectDigestInfo">,
		object_digest_info
	>>
>;

using v2_form = sequence_with_options<
	opts::named<"V2Form">,
	optional<x509::ext::general_names<"issuerName">>,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"baseCertificateID">,
		issuer_serial
	>>,
	optional<tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"objectDigestInfo">,
		object_digest_info
	>>
>;

using attr_cert_issuer = choice_with_options<
	opts::named<"AttCertIssuer">,
	x509::ext::general_names<"v1Form">,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"v2Form">,
		v2_form
	>
>;

using attribute_certificate_info = sequence_with_options<
	opts::named<"AttributeCertificate">,
	integer<opts::named<"version">>, //version is v2 = 1
	holder,
	attr_cert_issuer,
	algorithm_identifier<"signature">,
	integer<opts::named<"serialNumber">>,
	attr_cert_validity_period,
	sequence_of_with_options<
		opts::named<"attributes">,
		attribute<"attribute">
	>,
	optional<bit_string<opts::named<"issuerUniqueID">>>,
	optional<x509::extensions>
>;

using attribute_certificate = sequence_with_options<
	opts::named<"AttributeCertificate">,
	attribute_certificate_info,
	algorithm_identifier<"signatureAlgorithm">,
	bit_string<opts::named<"signatureValue">>
>;

using attribute_certificate_v2 = attribute_certificate;

using other_certificate_format = sequence_with_options<
	opts::named<"OtherCertificateFormat">,
	object_identifier<opts::named<"otherCertFormat">>,
	any<opts::named<"otherCert">>
>;

using certificate_choices = choice_with_options<
	opts::named<"CertificateChoices">,
	certificate,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"extendedCertificate">,
		extended_certificate
	>,
	tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"v1AttrCert">,
		attribute_certificate_v1
	>,
	tagged_with_options<2, encoding::impl, cls::context_specific,
		opts::named<"v2AttrCert">,
		attribute_certificate_v2
	>,
	tagged_with_options<3, encoding::impl, cls::context_specific,
		opts::named<"other">,
		other_certificate_format
	>
>;

namespace ms_bug_workaround
{
using certificate_choices = choice_with_options<
	opts::named<"CertificateChoices">,
	certificate,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"extendedCertificate">,
		extended_certificate
	>,
	//Microsoft has a bug in RFC5652 implementation.
	//v2AttrCert is tagged with 1 instead of 2.
	tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"v2AttrCert">,
		attribute_certificate_v2
	>,
	tagged_with_options<3, encoding::impl, cls::context_specific,
		opts::named<"other">,
		other_certificate_format
	>
>;

using certificate_set = set_of_with_options<opts::named<"certSet">,
	certificate_choices
>;
} //namespace ms_bug_workaround

using certificate_set = set_of_with_options<opts::named<"certSet">,
	certificate_choices
>;

using signer_identifier = choice_with_options<
	opts::named<"SignerIdentifier">,
	issuer_and_serial_number,
	tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"subjectKeyIdentifier">,
		x509::ext::subject_key_identifier
	>
>;

using signature_value = octet_string<opts::named<"signature">>;

using signed_attributes = authenticated_attributes;
using unsigned_attributes = unauthenticated_attributes;

using signer_info = sequence_with_options<opts::named<"SignerInfo">,
	//Only one info for authenticode
	integer<opts::named<"CMSVersion">>,
	signer_identifier,
	digest_algorithm_identifier,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"signedAttrs">,
		signed_attributes
	>>,
	algorithm_identifier<"signatureAlgorithm">,
	signature_value,
	optional<tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"unsignedAttrs">,
		unsigned_attributes
	>>
>;

using signer_infos = set_of_with_options<opts::named<"siSet">,
	signer_info
>;

template<typename ContentInfo, typename CertificateSet>
using signed_data_base = sequence_with_options<opts::named<"SignedData">,
	integer<opts::named<"CMSVersion">>,
	digest_algorithm_identifiers,
	ContentInfo,
	optional<tagged_with_options<0, encoding::impl, cls::context_specific,
		opts::named<"certificates">,
		CertificateSet
	>>,
	//optional<tagged_with_options<1, encoding::impl, cls::context_specific, opts::named<"crls">,
	//	revocation_info_choices //Not implemented
	//>>,
	signer_infos
>;

template<typename ContentInfo, typename CertificateSet>
using content_info_base_with_cert_type = sequence_with_options<opts::named<"CMSContentInfo">,
	object_identifier<opts::named<"contentType">>,
	tagged_with_options<0, encoding::expl, cls::context_specific,
		opts::named<"content">, signed_data_base<ContentInfo, CertificateSet>>
>;

template<typename ContentInfo>
using content_info_base = content_info_base_with_cert_type<ContentInfo, certificate_set>;

namespace ms_bug_workaround
{
template<typename ContentInfo>
using content_info_base = content_info_base_with_cert_type<ContentInfo, certificate_set>;
} //namespace ms_bug_workaround

} //namespace asn1::spec::crypto::pkcs7::cms
