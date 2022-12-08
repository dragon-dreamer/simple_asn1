#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <codecvt>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <locale>
#include <sstream>
#include <span>
#include <string>
#include <variant>

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm_ext/erase.hpp>

#include "simple_asn1/crypto/algorithms.h"
#include "simple_asn1/crypto/x509/extensions_spec.h"
#include "simple_asn1/crypto/x509/extensions_types.h"
#include "simple_asn1/crypto/x509/spec.h"
#include "simple_asn1/crypto/x509/types.h"
#include "simple_asn1/crypto/x520/spec.h"
#include "simple_asn1/crypto/x520/types.h"
#include "simple_asn1/der_decode.h"

namespace
{
std::string decode_base64(const std::string& val)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(
        std::string(It(std::begin(val)), It(std::end(val))),
        [](char c) {
            return c == '\0';
        });
}

template<typename Oid1, typename Oid2>
bool oids_equal(const Oid1& oid1, const Oid2& oid2)
{
    if (oid1.size() != oid2.size())
        return false;

    return std::equal(oid1.begin(), oid1.end(), oid2.begin());
}

template<typename Oid>
struct oid_description
{
    oid_description(const Oid& oid, const char* description)
        : oid(oid)
        , description(description)
    {
    }

    const Oid& oid;
    const char* description;
};
template<typename Oid>
oid_description(Oid, const char*) -> oid_description<Oid>;

template<typename Oid, typename MatchingOid>
bool describe_single_oid(std::ostream& stream,
    const Oid& oid, const oid_description<MatchingOid>& description)
{
    if (!oids_equal(oid, description.oid))
        return false;

    stream << asn1::oid_to_string(oid) << ' ' << description.description << '\n';
    return true;
}

template<typename Oid, typename... Oids>
void describe_oid(std::ostream& stream,
    const Oid& oid, const oid_description<Oids>&... descriptions)
{
    if (!(... || describe_single_oid(stream, oid, descriptions)))
        stream << asn1::oid_to_string(oid) << '\n';
}

void print_asn1_error(const asn1::parse_error& e)
{
    std::cerr << "ASN1 parse error: " << e.what() << '\n';
    if (!e.get_context().empty())
    {
        std::cerr << "Context: ";
        const char* sep = "";
        for (const auto& ctx : e.get_context())
        {
            std::cerr << sep << ctx.spec_type;
            if (!ctx.spec_name.empty())
                std::cerr << " (" << ctx.spec_name << ")";
            sep = "\n -> ";
        }
        std::cerr << '\n';
    }
}

void print_date_time(std::ostream& stream, const asn1::utc_time& date_time)
{
    stream << (date_time.year + 2000u) << '-' << std::setfill('0')
        << std::setw(2) << static_cast<std::uint32_t>(date_time.month)
        << std::setw(0) << '-'
        << std::setw(2) << static_cast<std::uint32_t>(date_time.day)
        << std::setw(0) << ' '
        << std::setw(2) << static_cast<std::uint32_t>(date_time.hour)
        << std::setw(0) << ':'
        << std::setw(2) << static_cast<std::uint32_t>(date_time.minute)
        << std::setw(0) << ':'
        << std::setw(2) << static_cast<std::uint32_t>(date_time.second);
}

void print_date_time(std::ostream& stream,
    const asn1::generalized_time& date_time)
{
    stream << date_time.year << '-' << std::setfill('0')
        << std::setw(2) << static_cast<std::uint32_t>(date_time.month)
        << std::setw(0) << '-'
        << std::setw(2) << static_cast<std::uint32_t>(date_time.day)
        << std::setw(0) << ' '
        << std::setw(2) << static_cast<std::uint32_t>(date_time.hour)
        << std::setw(0) << ':'
        << std::setw(2) << static_cast<std::uint32_t>(date_time.minute)
        << std::setw(0) << ':'
        << std::setw(2) << static_cast<std::uint32_t>(date_time.second);
    if (date_time.seconds_fraction)
        stream << std::setw(0) << '.' << date_time.seconds_fraction;
}

void print_date_time(std::ostream& stream, const asn1::crypto::time_type& date_time)
{
    std::visit([&stream](const auto& value) {
        return print_date_time(stream, value); }, date_time);
}

void print_attribute_type_name(std::ostream& stream,
    const asn1::crypto::object_identifier_type& oid)
{
    using namespace asn1::crypto::x520;
    describe_oid(stream, oid.container,
        oid_description(id_at_common_name, "(Common Name)"),
        oid_description(id_at_country_name, "(Country Name)"),
        oid_description(id_at_dn_qualifier, "(DN Qualifier)"),
        oid_description(id_domain_component, "(Domain Component)"),
        oid_description(id_email_address, "(Email Address)"),
        oid_description(id_at_generation_qualifier, "(Generation Qualifier)"),
        oid_description(id_at_given_name, "(Given Name)"),
        oid_description(id_at_initials, "(Initials)"),
        oid_description(id_at_locality_name, "(Locality Name)"),
        oid_description(id_at_name, "(Name)"),
        oid_description(id_at_organizational_unit_name, "(Organizational Unit Name)"),
        oid_description(id_at_organization_name, "(Organization Name)"),
        oid_description(id_at_pseudonim, "(Pseudonim)"),
        oid_description(id_at_serial_number, "(Serial Number)"),
        oid_description(id_at_state_or_province_name, "(State or Province Name)"),
        oid_description(id_at_surname, "(Surname)"),
        oid_description(id_at_title, "(Title)"));
}

void print_string(std::ostream& stream, const std::string& str)
{
    stream << str;
}

void print_string(std::ostream& stream, const std::u16string& str)
{
    std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter;
    stream << converter.to_bytes(str);
}

void print_string(std::ostream& stream, const std::u32string& str)
{
    std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> converter;
    stream << converter.to_bytes(str);
}

void print_directory_string(std::ostream& stream,
    const asn1::crypto::directory_string& str)
{
    std::visit([&stream](const auto& value) {
        print_string(stream, value);
    }, str);
}

void format_attribute_value(std::ostream& stream,
    const asn1::crypto::attribute_value_assertion<std::span<const std::uint8_t>>& attr)
{
    using namespace asn1::crypto::x520;
    if (oids_equal(attr.attribute_type.container, id_at_common_name)
        || oids_equal(attr.attribute_type.container, id_at_locality_name)
        || oids_equal(attr.attribute_type.container, id_at_state_or_province_name)
        || oids_equal(attr.attribute_type.container, id_at_name)
        || oids_equal(attr.attribute_type.container, id_at_organization_name)
        || oids_equal(attr.attribute_type.container, id_at_organizational_unit_name)
        || oids_equal(attr.attribute_type.container, id_at_title)
        || oids_equal(attr.attribute_type.container, id_at_pseudonim)
        || oids_equal(attr.attribute_type.container, id_at_surname)
        || oids_equal(attr.attribute_type.container, id_at_given_name)
        || oids_equal(attr.attribute_type.container, id_at_initials)
        || oids_equal(attr.attribute_type.container, id_at_generation_qualifier))
    {
        auto result = asn1::der::decode<
            asn1::crypto::directory_string,
            asn1::spec::crypto::directory_string<"Attr">>(
                attr.attribute_value.begin(), attr.attribute_value.end());
        print_directory_string(stream, result);
        return;
    }
    
    if (oids_equal(attr.attribute_type.container, id_at_country_name)
        || oids_equal(attr.attribute_type.container, id_at_dn_qualifier)
        || oids_equal(attr.attribute_type.container, id_at_serial_number))
    {
        auto result = asn1::der::decode<
            std::string,
            asn1::spec::printable_string<asn1::opts::named<"Attr">>>(
                attr.attribute_value.begin(), attr.attribute_value.end());
        print_string(stream, result);
        return;
    }

    if (oids_equal(attr.attribute_type.container, id_domain_component)
        || oids_equal(attr.attribute_type.container, id_email_address))
    {
        auto result = asn1::der::decode<
            std::string,
            asn1::spec::ia5_string<asn1::opts::named<"Attr">>>(
                attr.attribute_value.begin(), attr.attribute_value.end());
        print_string(stream, result);
        return;
    }
}

void format_names(std::ostream& stream,
    const asn1::crypto::name_type<std::span<const std::uint8_t>>& names)
{
    for (const auto& name : names)
    {
        stream << "  Name:\n";
        for (const auto& attr : name)
        {
            stream << "    Attribute: ";
            print_attribute_type_name(stream, attr.attribute_type);
            stream << "    Value: ";
            try
            {
                format_attribute_value(stream, attr);
            }
            catch (const asn1::parse_error& e)
            {
                stream << '\n';
                print_asn1_error(e);
            }
            stream << '\n';
        }
    }
    stream << '\n';
}

void print_key_usage_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Key usage extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::key_usage<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::key_usage>(value.begin(), value.end());

    if (!result.bit_count)
        return;

    using asn1::crypto::x509::ext::key_usage_bits;
    if (result.is_set(key_usage_bits::content_commitment))
        stream << " * Content Commitment\n";
    if (result.is_set(key_usage_bits::crl_sign))
        stream << " * CRL Sign\n";
    if (result.is_set(key_usage_bits::data_encipherment))
        stream << " * Data Encipherment\n";
    if (result.is_set(key_usage_bits::decipher_only))
        stream << " * Decipher Only\n";
    if (result.is_set(key_usage_bits::digital_signature))
        stream << " * Digital Signature\n";
    if (result.is_set(key_usage_bits::encipher_only))
        stream << " * Encipher Only\n";
    if (result.is_set(key_usage_bits::key_agreement))
        stream << " * Key Agreement\n";
    if (result.is_set(key_usage_bits::key_cert_sign))
        stream << " * Key Cert Sign\n";
    if (result.is_set(key_usage_bits::key_encipherment))
        stream << " * Key Encipherment\n";
}

void print_ext_key_usage_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Ext key usage extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::ext_key_usage_syntax,
        asn1::spec::crypto::x509::ext::ext_key_usage_syntax>(value.begin(), value.end());

    using namespace asn1::crypto::x509::ext;
    for (const auto& usage : result)
    {
        stream << "Usage: ";
        describe_oid(stream, usage.container,
            oid_description(id_kp_server_auth, "(Server Auth)"),
            oid_description(id_kp_client_auth, "(Client Auth)"),
            oid_description(id_kp_code_signing, "(Code Signing)"),
            oid_description(id_kp_email_protection, "(Email Protection)"),
            oid_description(id_kp_time_stamping, "(Time Stamping)"),
            oid_description(id_kp_ocsp_signing, "(OSCP Signing)"),
            oid_description(id_kp_ocsp_basic, "(OSCP Basic)"),
            oid_description(id_kp_ocsp_nonce, "(OSCP Nonce)"),
            oid_description(id_kp_ocsp_crl, "(OSCP CRL)"),
            oid_description(id_kp_ocsp_response, "(OSCP Response)"),
            oid_description(id_kp_ocsp_nocheck, "(OSCP Nocheck)"),
            oid_description(id_kp_ocsp_archive_cutoff, "(OSCP Archive Cutoff)"),
            oid_description(id_kp_ocsp_service_locator, "(OSCP Service Locator)"),
            oid_description(id_kp_dvcs_data_validation_and_certification_server, "(DVCS)"),
            oid_description(id_kp_eap_over_ppp, "(EAP Over PPP)"),
            oid_description(id_kp_eap_over_lan, "(EAP Over LAN)"),
            oid_description(id_kp_scvp_server, "(SCVP Server)"),
            oid_description(id_kp_scvp_client, "(SCVP Client)"),
            oid_description(id_kp_ipsec_ike, "(IPSEC IKE)"),
            oid_description(id_kp_capwap_ac, "(Capwap AC)"),
            oid_description(id_kp_capwap_wtp, "(Capwap WTP)"),
            oid_description(id_kp_sip_domain, "(SIP Domain)"),
            oid_description(id_kp_secure_shell_client, "(KP Secure Shell Client)"),
            oid_description(id_kp_secure_shell_server, "(KP Secure Shell Server)"),
            oid_description(id_kp_send_router, "(Send Router)"),
            oid_description(id_kp_send_proxied_router, "(Send Proxied Router)"),
            oid_description(id_kp_send_owner, "(Send Owner)"),
            oid_description(id_kp_send_proxied_owner, "(Send Proxied Owner)"),
            oid_description(id_kp_cmc_ca, "(CMC CA)"),
            oid_description(id_kp_cmc_ra, "(CMC RA)"),
            oid_description(id_kp_cmc_archive, "(CMC Archive)"),
            oid_description(id_kp_bgpsec_router, "(Bgpsec Router)"),
            oid_description(id_kp_brand_indicator_for_message_identification,
                "(Brand Indicator For Message Identification)"),
            oid_description(id_kp_cm_kga, "(CM KGA)"),
            oid_description(id_kp_rpc_tls_client, "(RPC TLS Client)"),
            oid_description(id_kp_rpc_tls_server, "(RPC TLS Server)"),
            oid_description(id_kp_bundle_security, "(Bundle Security)"),
            oid_description(id_kp_document_signing, "(Document Signing)"));
    }
}

void print_basic_constraints_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Basic constraints extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::basic_constraints,
        asn1::spec::crypto::x509::ext::basic_constraints>(value.begin(), value.end());

    stream << "CA: " << (result.ca ? "YES" : "NO") << '\n';
    if (result.path_len_constraint)
        stream << "Path length constraint: " << *result.path_len_constraint << '\n';
}

template<typename Container>
void print_binary(std::ostream& stream, const Container& container)
{
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0, count = 0; i != container.size(); ++i)
    {
        stream << std::setw(2) << static_cast<std::uint32_t>(container[i])
            << std::setw(0) << ' ';
        if (++count == 20 && i != container.size() - 1)
        {
            count = 0;
            stream << '\n';
        }
    }
    stream << '\n';
}

void print_serial_number(std::ostream& stream, std::span<const std::uint8_t> bytes)
{
    stream << "Serial number: ";
    print_binary(stream, bytes);
}

void print_subject_key_id_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Subject key identifier extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::subject_key_identifier<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::subject_key_identifier>(value.begin(), value.end());
    print_binary(stream, result);
}

void print_authority_key_id_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Authority key identifier extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::authority_key_identifier<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::authority_key_identifier>(value.begin(), value.end());

    if (result.key_id)
    {
        stream << "Key ID:\n";
        print_binary(stream, *result.key_id);
    }

    if (result.certificate_serial_number)
    {
        stream << "Certificate Serial Number:\n";
        print_binary(stream, *result.certificate_serial_number);
    }

    //TODO: print result.authority_cert_issuer
}

template<typename T>
void print_name(std::ostream& stream, const T&)
{
    //TODO: support other name types for general_name
    stream << "(unsupported)";
}

void print_name(std::ostream& stream, const std::string& name)
{
    print_string(stream, name);
}

void print_name(std::ostream& stream, const asn1::crypto::object_identifier_type& oid)
{
    stream << asn1::oid_to_string(oid.container);
}

void print_name(std::ostream& stream, const std::span<const std::uint8_t>& value)
{
    print_binary(stream, value);
}

void print_general_name(std::ostream& stream,
    const asn1::crypto::x509::ext::general_name<std::span<const std::uint8_t>>& name)
{
    switch (name.index())
    {
    case 0: stream << "Other name: "; break;
    case 1: stream << "RFC822 name: "; break;
    case 2: stream << "DNS name: "; break;
    case 3: stream << "X400 address: "; break;
    case 4: stream << "Directory name: "; break;
    case 5: stream << "Edi party name: "; break;
    case 6: stream << "Uniform resource identifier: "; break;
    case 7: stream << "IP address: "; break;
    case 8: stream << "Registered ID: "; break;
    }
    std::visit([&stream](const auto& name) {
        print_name(stream, name);
    }, name);
    stream << '\n';
}

void print_subject_alt_name_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Subject alt name extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::subject_alt_name<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::subject_alt_name>(value.begin(), value.end());

    for (const auto& name : result)
        print_general_name(stream, name);
}

void print_certificate_policies_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Certificate policies extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::certificate_policies<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::certificate_policies>(value.begin(), value.end());

    for (const auto& policy : result)
    {
        stream << "Policy ID: ";
        using namespace asn1::crypto::x509::ext;
        describe_oid(stream, policy.policy_identifier.container,
            oid_description(id_ca_browser_forum_domain_validated,
                "(CA/Browser Forum domain-validated)"),
            oid_description(id_ca_browser_forum_organization_validated,
                "(CA/Browser Forum organization-validated)"),
            oid_description(id_ca_browser_forum_individual_validated,
                "(CA/Browser Forum individual-validated)"),
            oid_description(id_ca_browser_forum_code_signing,
                "(CA/Browser Forum code-signing)"),
            oid_description(id_google_trust_services,
                "(Google Trust Services)"),
            oid_description(id_google_internet_authority_g2,
                "(Google Internet Authority G2)"));

        if (policy.policy_qualifiers)
        {
            for (const auto& qualifier : *policy.policy_qualifiers)
            {
                stream << "Policy qualifier: ";
                describe_oid(stream, qualifier.policy_qualifier_id.container,
                    oid_description(id_qt_cps, "(CPS pointer qualifier)"),
                    oid_description(id_qt_unotice, "(user notice qualifier)"));

                if (oids_equal(qualifier.policy_qualifier_id.container, id_qt_cps))
                {
                    stream << "CPS URI: " << asn1::der::decode<asn1::crypto::x509::ext::cps_uri,
                        asn1::spec::crypto::x509::ext::cps_uri>(
                            qualifier.qualifier.begin(), qualifier.qualifier.end()) << '\n';
                }
                else if (oids_equal(qualifier.policy_qualifier_id.container, id_qt_unotice))
                {
                    stream << "User notice\n";
                    //TODO: support user notice
                }
            }
        }
    }
}

void print_crl_distribution_points_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "CRL distribution points extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::crl_distribution_points<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::crl_distribution_points>(value.begin(), value.end());

    for (const auto& point : result)
    {
        if (point.distr_point)
        {
            const auto* general_names = std::get_if<
                asn1::crypto::x509::ext::general_names<std::span<const std::uint8_t>>>(
                    &*point.distr_point);
            if (general_names)
            {
                for (const auto& general_name : *general_names)
                    print_general_name(stream, general_name);
            }
            else
            {
                stream << "(unsupported name)\n"; //TODO: support RelativeDistinguishedName
            }
        }
    }
}

void print_authority_info_access_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Authority info access extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::authority_info_access_syntax<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::authority_info_access_syntax>(value.begin(), value.end());

    for (const auto& info : result)
    {
        print_general_name(stream, info.access_location);
        stream << "Access method: ";
        using namespace asn1::crypto::x509::ext;
        describe_oid(stream, info.access_method.container,
            oid_description(id_ad_ocsp, "(OCSP)"),
            oid_description(id_ad_ca_issuers, "(CA Issuers)"),
            oid_description(id_ad_timestamping, "(Timestamping)"),
            oid_description(id_ad_ca_repository, "(CA Repository)"));
    }
}

void print_signed_certificate_timestamp_list_extension(std::ostream& stream,
    std::span<const std::uint8_t> value)
{
    stream << "Signed certificate timestamp list extension\n";

    auto result = asn1::der::decode<asn1::crypto::x509::ext::signed_certificate_timestamp_list<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::ext::signed_certificate_timestamp_list>(value.begin(), value.end());

    stream << "TLS-encoded data (not supported)\n";
    print_binary(stream, result);
}

void print_extension(std::ostream& stream,
    const asn1::crypto::x509::extension<std::span<const std::uint8_t>>& extension)
{
    stream << "ID: " << asn1::oid_to_string(extension.extnid.container) << '\n';
    stream << "Critical: " << (extension.critical ? "YES" : "NO") << '\n';

    using namespace asn1::crypto::x509::ext;
    try
    {
        if (oids_equal(extension.extnid.container, id_ce_key_usage))
            print_key_usage_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_ext_key_usage))
            print_ext_key_usage_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_basic_constraints))
            print_basic_constraints_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_subject_key_identifier))
            print_subject_key_id_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_authority_key_identifier))
            print_authority_key_id_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_subject_alt_name))
            print_subject_alt_name_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_certificate_policies))
            print_certificate_policies_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_ce_crl_distribution_points))
            print_crl_distribution_points_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_pe_authority_info_access))
            print_authority_info_access_extension(stream, extension.extnValue);
        else if (oids_equal(extension.extnid.container, id_sct_precert_signed_certificate_timestamp_list))
            print_signed_certificate_timestamp_list_extension(stream, extension.extnValue);
    }
    catch (const asn1::parse_error& e)
    {
        print_asn1_error(e);
    }
}

void print_extensions(std::ostream& stream,
    const std::optional<asn1::crypto::x509::extensions_type<std::span<const std::uint8_t>>>& extensions)
{
    if (!extensions)
        return;

    stream << "Extensions:\n\n";
    for (const auto& extension : *extensions)
    {
        print_extension(stream, extension);
        stream << '\n';
    }
}

void print_signature_algorithm(std::ostream& stream,
    const asn1::crypto::object_identifier_type& oid)
{
    using namespace asn1::crypto::signature;
    stream << "Signature algorithm: ";
    describe_oid(stream, oid.container,
        oid_description(id_sha1_with_rsa_encryption, "SHA1 with RSA"),
        oid_description(id_sha224_with_rsa_encryption, "SHA256 with RSA"),
        oid_description(id_sha256_with_rsa_encryption, "SHA256 with RSA"),
        oid_description(id_sha384_with_rsa_encryption, "SHA384 with RSA"),
        oid_description(id_sha512_with_rsa_encryption, "SHA512 with RSA"));
}
void print_pki_algorithm(std::ostream& stream,
    const asn1::crypto::object_identifier_type& oid)
{
    using namespace asn1::crypto::pki;
    stream << "PKI algorithm: ";
    describe_oid(stream, oid.container,
        oid_description(id_dh_public_number, "DH public number"),
        oid_description(id_dsa, "DSA"),
        oid_description(id_ec_public_key, "EC public key"),
        oid_description(id_rsa, "RSA"));
}
} //namespace

int main(int argc, const char* argv[]) try
{
    if (argc < 2)
    {
        std::cerr << "Specify the x509 certificate path" << std::endl;
        return -1;
    }

    std::string x509_cert;
    {
        std::ifstream file;
        file.exceptions(std::ios::badbit | std::ios::failbit);
        file.open(argv[1], std::ios::in | std::ios::binary);
        file.seekg(0, std::ios::end);
        auto size = static_cast<std::size_t>(file.tellg());
        x509_cert.resize(size);
        file.seekg(0);
        file.read(&x509_cert[0], size);
    }

    boost::algorithm::erase_first(x509_cert, "-----BEGIN CERTIFICATE-----");
    boost::algorithm::erase_first(x509_cert, "-----END CERTIFICATE-----");
    boost::remove_erase_if(x509_cert, boost::algorithm::is_any_of("\r\n\t "));

    x509_cert = decode_base64(x509_cert);
    const auto* begin = reinterpret_cast<const std::uint8_t*>(x509_cert.data());

    auto result = asn1::der::decode<asn1::crypto::x509::certificate<
        std::span<const std::uint8_t>>,
        asn1::spec::crypto::x509::certificate>(begin, begin + x509_cert.size());
    print_signature_algorithm(std::cout, result.signature_algorithm.algorithm);
    print_pki_algorithm(std::cout, result.tbs_cert.pki.algorithm.algorithm);
    std::cout << "Version: " << result.tbs_cert.version << '\n';
    std::cout << "Valid not before: ";
    print_date_time(std::cout, result.tbs_cert.valid.not_before);
    std::cout << "\nValid not after: ";
    print_date_time(std::cout, result.tbs_cert.valid.not_after);
    std::cout << '\n';
    print_serial_number(std::cout, result.tbs_cert.serial_number);
    std::cout << "Issuer: \n";
    format_names(std::cout, result.tbs_cert.issuer);
    std::cout << "\nSubject: \n";
    format_names(std::cout, result.tbs_cert.subject);
    print_extensions(std::cout, result.tbs_cert.extensions);
    return 0;
}
catch (const asn1::parse_error& e)
{
    print_asn1_error(e);
    return -1;
}
catch (const std::exception& e)
{
    std::cerr << "Error: " << e.what() << '\n';
    return -1;
}
