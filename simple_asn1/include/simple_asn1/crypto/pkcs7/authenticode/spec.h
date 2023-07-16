// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/crypto/pkcs7/spec.h"
#include "simple_asn1/crypto/x509/spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::pkcs7::authenticode
{
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

using spc_attribute_page_hashes = set_of_with_options<
	opts::named<"SpcAttributePageHashes">,
	sequence_with_options<
		opts::named<"SpcAttributePageHashes">,
		object_identifier<opts::named<"type">>,
		set_of_with_options<opts::named<"hashes">,
			octet_string<opts::named<"hashes">>
		>
	>
>;

using spc_sp_opus_info = sequence_with_options<
	opts::named<"DigestInfo">,
	spec::optional<tagged_with_options<0, encoding::expl, cls::context_specific,
		opts::named<"programName">,
		spc_string>
	>,
	spec::optional<tagged_with_options<1, encoding::expl, cls::context_specific,
		opts::named<"moreInfo">,
		spc_link>
	>
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

using content_info = content_info_base<encap_content_info>;
} //namespace asn1::spec::crypto::pkcs7::authenticode
