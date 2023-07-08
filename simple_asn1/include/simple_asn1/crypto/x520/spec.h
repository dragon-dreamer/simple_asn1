// SPDX-License-Identifier: MIT

#pragma once

#include "simple_asn1/crypto/crypto_common_spec.h"
#include "simple_asn1/spec.h"

namespace asn1::spec::crypto::x520
{
using name = directory_string<"x520_name">;
using common_name = directory_name<"x520_common_name">;
using locality_name = directory_name<"x520_locality_name">;
using state_or_province_name = directory_name<"x520_state_or_province_name">;
using organization_name = directory_name<"x520_organization_name">;
using organizational_unit_name = directory_name<"x520_organizational_unit_name">;
using title = directory_name<"x520_title">;
using pseudonim = directory_name<"x520_pseudonim">;

using dn_qualifier = printable_string<opts::named<"x520_dn_qualifier">>;
using country_name = printable_string<opts::named<"x520_country_name">>;
using serial_number = printable_string<opts::named<"x520_serial_number">>;

using domain_component = ia5_string<opts::named<"x520_comain_component">>;
using email_address = ia5_string<opts::named<"x520_email_address">>;
} //namespace asn1::spec::crypto::x520
