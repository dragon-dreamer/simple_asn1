// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::x509
{
using validity = sequence_with_options<opts::named<"validity">,
	time<"notBefore">,
	time<"notAfter">
>;

using subject_public_key_info = sequence_with_options<opts::named<"SubjectPublicKeyInfo">,
	algorithm_identifier<"algorithm">,
	bit_string<opts::named<"subjectPublicKey">>
>;

template<detail::compile_time_string Name>
using unique_identifier = bit_string<opts::named<Name>>;

using extension = sequence_with_options<opts::named<"extension">,
	object_identifier<opts::named<"extnid">>,
	optional_default<default_value<false>, boolean<opts::named<"critical">>>,
	octet_string<opts::named<"extnValue">>
>;

using extensions = sequence_of_with_options<opts::named<"extensions">,
	extension
>;

using tbs_certificate = sequence_with_options<opts::named<"TBSCertificate">,
	tagged_with_options<0, encoding::expl, cls::context_specific, opts::named<"version">,
		integer<opts::named<"version">>
	>,
	integer<opts::named<"serialNumber">>,
	algorithm_identifier<"signature">,
	name<"issuer">,
	validity,
	name<"subject">,
	subject_public_key_info,
	optional<tagged_with_options<1, encoding::impl, cls::context_specific,
		opts::named<"issuerUniqueID">,
		unique_identifier<"issuerUniqueID">
	>>,
	optional<tagged_with_options<2, encoding::impl, cls::context_specific,
		opts::named<"subjectUniqueID">,
		unique_identifier<"subjectUniqueID">
	>>,
	optional<tagged_with_options<3, encoding::expl, cls::context_specific,
		opts::named<"extensions">,
		extensions
	>>
>;

template<detail::compile_time_string Name>
using certificate_base = sequence_with_options<opts::named<Name>,
	tbs_certificate,
	algorithm_identifier<"signatureAlgorithm">,
	bit_string<opts::named<"signature">>
>;

using certificate = certificate_base<"X.509">;
} //namespace asn1::spec::crypto::x509
