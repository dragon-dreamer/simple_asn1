// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/crypto/x509/extensions_spec.h"
#include "simple_asn1/crypto/x509/spec.h"

namespace asn1::spec::crypto::tst
{

using accuracy = sequence_with_options<
    opts::named<"Accuracy">,
    optional<integer<opts::named<"seconds">>>,
    optional<tagged_with_options<0u, encoding::impl, cls::context_specific,
		opts::named<"millis">,
		integer<opts::named<"millis">>
	>>,
    optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
		opts::named<"micros">,
		integer<opts::named<"micros">>
	>>
>;

using message_imprint = sequence_with_options<
    opts::named<"MessageImprint">,
    algorithm_identifier<"hashAlgorithm">,
    octet_string<opts::named<"hashedMessage">>
>;

using tst_info = sequence_with_options<
    opts::named<"TSTInfo">,
    integer<opts::named<"version">>,
    object_identifier<opts::named<"TSAPolicyId">>,
    message_imprint,
    integer<opts::named<"serialNumber">>,
    generalized_time<opts::named<"genTime">>,
    optional<accuracy>,
    optional_default<default_value<false>, boolean<opts::named<"ordering">>>,
    optional<integer<opts::named<"nonce">>>,
    optional<tagged_with_options<0u, encoding::expl, cls::context_specific,
        opts::named<"tsa">,
        x509::ext::general_name<"tsa">
    >>,
    optional<tagged_with_options<1u, encoding::impl, cls::context_specific,
        opts::named<"tsa">,
        x509::extensions
    >>
>;

using encap_tst_info = sequence_with_options<
    opts::named<"encapsulatedTSTInfo">,
    object_identifier<opts::named<"contentType">>,
    tagged_with_options<0u, encoding::expl, cls::context_specific,
        opts::named<"encapsulatedTSTInfo">,
        octet_string_with<tst_info>
    >
>;

} //namespace asn1::spec::crypto::tst
