// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>

#include "simple_asn1/types.h"

namespace asn1
{
namespace detail
{
struct recursive_base {};

template<tag_type Tag>
struct spec_tag
{
	[[nodiscard]] static constexpr tag_type tag() noexcept
	{
		return Tag;
	}
};

template<std::size_t N>
struct compile_time_string final
{
	constexpr compile_time_string(const char(&s)[N]) noexcept
	{
		for (std::size_t i = 0; i != N; ++i)
			str[i] = s[i];
	}

	[[nodiscard]]
	constexpr operator const char* () const noexcept
	{
		return str;
	}

	char str[N];
};

template<std::size_t N> compile_time_string(const char(&)[N])
	-> compile_time_string<N>;

template<compile_time_string Name>
struct spec_type
{
	static constexpr compile_time_string spec_name{ Name };
};

enum class option_cat
{
	name,
	zero_year,
	validator,
	min_max_elements,
	max
};

template<option_cat Cat>
struct option_base
{
	static constexpr option_cat category = Cat;
};

struct dummy_option final : option_base<option_cat::max> {};

template<typename Spec, option_cat Cat>
struct option_helper
{
	using option_type = typename Spec
		::template option_by_category<Cat>;
};

template<typename Spec>
concept RecursiveSpec = std::is_base_of_v<recursive_base, Spec>;

template<RecursiveSpec Spec, option_cat Cat>
struct option_helper<Spec, Cat>
{
	using option_type = typename Spec::type
		::template option_by_category<Cat>;
};

template<typename Spec, option_cat Cat>
using option_by_cat = typename option_helper<Spec, Cat>::option_type;

template<typename Spec>
static constexpr auto spec_name_by_spec = std::conditional_t<
	RecursiveSpec<Spec>, Spec, std::type_identity<Spec>>::type::spec_name;
} //namespace detail

namespace opts
{
template<detail::compile_time_string Name>
struct name final : detail::option_base<detail::option_cat::name>
{
	static constexpr detail::compile_time_string value{ Name };
};

template<typename Validator>
struct validator final : detail::option_base<detail::option_cat::validator>
{
	using validator_type = Validator;
};

template<std::size_t Min, std::size_t Max>
struct min_max_elements final : detail::option_base<detail::option_cat::min_max_elements>
{
	static_assert(Min <= Max);
	static constexpr std::size_t min_elems{ Min };
	static constexpr std::size_t max_elems{ Max };
};

template<auto Validator>
using validator_func = validator<decltype(Validator)>;

template<std::uint16_t ZeroYearValue>
struct zero_year final
	: detail::option_base<detail::option_cat::zero_year>
{
	static_assert(ZeroYearValue >= 100);
	static constexpr auto value = ZeroYearValue;
};

template<typename... Options>
struct options {};

template<detail::compile_time_string Name>
using named = options<name<Name>>;
} //namespace opts

namespace detail
{
template<option_cat... Categories>
struct optional_options final {};

template<typename Optional, typename Provided>
struct options_parser final {};

template<option_cat... Optional, typename Provided>
struct options_parser<optional_options<Optional...>, Provided>
{
	static_assert(sizeof...(Optional) > 100000,
		"Provided options must be wrapped into opts::options template");
};

template<option_cat... Optional, typename... Provided>
struct options_parser<optional_options<Optional...>, opts::options<Provided...>>
{
public:
	template<option_cat Cat, typename Option, typename... Options>
	static constexpr auto type_by_category()
	{
		if constexpr (Option::category == Cat)
			return Option{};
		else if constexpr (sizeof...(Options) != 0u)
			return type_by_category<Cat, Options...>();
	}

public:
	template<option_cat Option>
	using option_by_category = decltype(type_by_category<Option,
		Provided..., dummy_option>());

	template<option_cat Option>
	static constexpr bool has_option = !std::is_same_v<
		option_by_category<Option>, void>;

private:
	struct option_check_result
	{
		bool has_unknown_option = false;
	};

	static constexpr option_check_result check_options()
	{
		option_check_result result{};
		if constexpr (sizeof...(Provided) > 0)
		{
			std::array<bool, static_cast<std::size_t>(option_cat::max)> optional{};
			(..., (optional[static_cast<std::size_t>(Optional)] = true));

			for (option_cat cat : { Provided::category... })
			{
				auto option_value = static_cast<std::size_t>(cat);
				if (option_value >= static_cast<std::size_t>(option_cat::max))
				{
					result.has_unknown_option = true;
					return result;
				}

				if (optional[option_value])
				{
					optional[option_value] = false;
				}
				else
				{
					result.has_unknown_option = true;
					return result;
				}
			}
		}

		return result;
	}

	static constexpr auto option_check = check_options();
	static_assert(!option_check.has_unknown_option,
		"Some provided options are not supported or duplicate");
};

template<typename Options>
using default_options_parser = detail::options_parser<
	detail::optional_options<detail::option_cat::name,
		detail::option_cat::validator>,
	Options>;

template<typename Spec>
struct spec_traits
{
	static constexpr bool is_constructed
		= (Spec::tag() & 0x20u) != 0u;
	static constexpr bool is_choice = false;
};

template<typename Spec>
struct optional_traits
{
	static constexpr bool is_optional = false;
	static constexpr bool has_default = false;
	using nested_spec_type = Spec;
};

template<typename Spec>
struct any_traits
{
	static constexpr bool is_any = false;
};

template<typename Spec>
struct extension_traits
{
	static constexpr bool is_extension_marker = false;
};
} //namespace detail

namespace spec
{
//TODO: these types are not yet supported
//[UNIVERSAL 8] EXTERNAL, INSTANCE OF
//[UNIVERSAL 9] REAL
//[UNIVERSAL 11] EMBEDDED PDV
//[UNIVERSAL 29] CHARACTER STRING

template<typename DerivedSpec>
struct recursive : detail::recursive_base
{
	[[nodiscard]] static constexpr tag_type tag() noexcept
	{
		return DerivedSpec::type::tag();
	}
};

template<typename Options = opts::options<>>
struct any : detail::spec_type<"ANY">, detail::default_options_parser<Options> {};
template<typename Options = opts::options<>>
struct boolean
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x01u>
	, detail::spec_type<"BOOLEAN"> {};
template<typename Options = opts::options<>>
struct integer
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x02u>
	, detail::spec_type<"INTEGER"> {};
template<typename Options = opts::options<>>
struct enumerated
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x0au>
	, detail::spec_type<"ENUMERATED"> {};
template<typename Options = opts::options<>>
struct null
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x05u>
	, detail::spec_type<"NULL"> {};

template<typename Options, typename Spec, typename... Specs>
struct sequence_with_options
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x30u>
	, detail::spec_type<"SEQUENCE"> {};
template<typename... Specs>
using sequence = sequence_with_options<opts::options<>, Specs...>;

template<typename Options = opts::options<>>
struct extension_marker final
	: detail::default_options_parser<Options>
	, detail::spec_type<"ExtensionMarker"> {};

template<typename Options, typename Spec>
struct sequence_of_with_options
	: detail::options_parser<
		detail::optional_options<detail::option_cat::name,
			detail::option_cat::min_max_elements,
			detail::option_cat::validator>, Options>
	, detail::spec_tag<0x30u>
	, detail::spec_type<"SEQUENCE OF"> {};
template<typename Spec>
using sequence_of = sequence_of_with_options<opts::options<>, Spec>;
template<typename Options, typename Spec>
struct set_of_with_options
	: detail::options_parser<
		detail::optional_options<detail::option_cat::name,
			detail::option_cat::min_max_elements,
			detail::option_cat::validator>, Options>
	, detail::spec_tag<0x31u>
	, detail::spec_type<"SET OF"> {};
template<typename Spec>
using set_of = set_of_with_options<opts::options<>, Spec>;

template<typename Options, typename Spec, typename... Specs>
struct choice_with_options
	: detail::default_options_parser<Options>
	, detail::spec_type<"CHOICE"> {};
template<typename... Specs>
using choice = choice_with_options<opts::options<>, Specs...>;

template<typename Options, typename Spec, typename... Specs>
struct set_with_options
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x31u>
	, detail::spec_type<"SET"> {};
template<typename... Specs>
using set = set_with_options<opts::options<>, Specs...>;

template<typename Options = opts::options<>>
struct octet_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x04u>
	, detail::spec_type<"OCTET STRING"> {};

template<typename Options = opts::options<>>
struct bit_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x03u>
	, detail::spec_type<"BIT STRING"> {};

template<typename Options = opts::options<>>
struct object_identifier
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x06u>
	, detail::spec_type<"OBJECT IDENTIFIER"> {};

template<typename Options = opts::options<>>
struct relative_oid
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x0du>
	, detail::spec_type<"RELATIVE-OID"> {};

template<typename Options = opts::options<>>
struct numeric_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x12u>
	, detail::spec_type<"NumericString"> {};

template<typename Options = opts::options<>>
struct printable_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x13u>
	, detail::spec_type<"PrintableString"> {};

template<typename Options = opts::options<>>
struct ia5_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x16u>
	, detail::spec_type<"IA5String"> {};

template<typename Options = opts::options<>>
struct teletex_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x14u>
	, detail::spec_type<"TeletexString"> {};

template<typename Options = opts::options<>>
struct videotex_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x15u>
	, detail::spec_type<"VideotexString"> {};

template<typename Options = opts::options<>>
struct visible_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x1au>
	, detail::spec_type<"VisibleString"> {};

template<typename Options = opts::options<>>
struct graphic_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x19u>
	, detail::spec_type<"GraphicString"> {};

template<typename Options = opts::options<>>
struct general_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x1bu>
	, detail::spec_type<"GeneralString"> {};

template<typename Options = opts::options<>>
struct object_descriptor
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x07u>
	, detail::spec_type<"ObjectDescriptor"> {};

template<typename Options = opts::options<>>
struct universal_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x1cu>
	, detail::spec_type<"UniversalString"> {};

template<typename Options = opts::options<>>
struct bmp_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x1eu>
	, detail::spec_type<"BMPString"> {};

template<typename Options = opts::options<>>
struct utf8_string
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x0cu>
	, detail::spec_type<"UTF8String"> {};

template<typename Options = opts::options<>>
struct generalized_time
	: detail::default_options_parser<Options>
	, detail::spec_tag<0x18u>
	, detail::spec_type<"GeneralizedTime"> {};

template<typename Options = opts::options<opts::zero_year<2000u>>>
struct utc_time
	: detail::options_parser<
		detail::optional_options<detail::option_cat::name,
			detail::option_cat::zero_year,
			detail::option_cat::validator>, Options>
	, detail::spec_tag<0x17u>
	, detail::spec_type<"UTCTime"> {};

enum class cls : std::uint8_t
{
	application = 0x40u,
	context_specific = 0x80u,
	priv = 0xc0u
};

enum class encoding : std::uint8_t
{
	impl = 0x00u,
	expl = 0x20u
};

template<std::uint8_t Tag, encoding Encoding,
	cls Class, typename Options, typename NestedSpec>
struct tagged_with_options
	: detail::default_options_parser<Options>
	, detail::spec_type<"TAGGED">
{
private:
	static_assert(Tag <= 0x1fu);

public:
	[[nodiscard]] static constexpr tag_type tag() noexcept
	{
		tag_type result = Tag | static_cast<std::uint8_t>(Class);
		if constexpr (Encoding == encoding::expl)
		{
			result |= 0x20u;
		}
		else
		{
			constexpr bool is_any = detail::any_traits<NestedSpec>::is_any;
			static_assert(!is_any, "ANY can not be tagged implicitly");
			if constexpr (!is_any)
			{
				if constexpr (detail::spec_traits<NestedSpec>::is_constructed)
					result |= 0x20u;
			}
		}
		return result;
	}
};

template<std::uint8_t Tag, encoding Encoding,
	cls Class, typename Field>
using tagged = tagged_with_options<
	Tag, Encoding, Class, opts::options<>, Field>;

template<typename Spec>
struct optional final : Spec {};

template<typename DefaultValueProvider, typename Spec>
struct optional_default final : Spec
{
	template<typename T>
	static constexpr void assign_default(T& value)
	{
		DefaultValueProvider::assign_default(value);
	}
};

template<auto Value>
struct default_value final
{
	template<typename T>
	static constexpr void assign_default(T& result)
	{
		result = Value;
	}
};
} //namespace spec

namespace detail
{
template<typename... Fields>
struct spec_traits<spec::choice_with_options<Fields...>> final
{
	static constexpr bool is_constructed = false;
	static constexpr bool is_choice = true;
};

template<typename... Fields>
struct spec_traits<spec::optional<spec::choice_with_options<Fields...>>> final
{
	static constexpr bool is_constructed = false;
	static constexpr bool is_choice = true;
};

template<typename DefaultValueProvider, typename... Fields >
struct spec_traits<spec::optional_default<DefaultValueProvider,
	spec::choice_with_options<Fields...>>> final
{
	static constexpr bool is_constructed = false;
	static constexpr bool is_choice = true;
};

template<typename Options>
struct spec_traits<spec::any<Options>> final
{
	static constexpr bool is_choice = false;
};

template<typename Spec>
struct optional_traits<spec::optional<Spec>> final
{
	static constexpr bool is_optional = true;
	static constexpr bool has_default = false;
};

template<typename DefaultValueProvider, typename Spec>
struct optional_traits<
	spec::optional_default<DefaultValueProvider, Spec>> final
{
	static constexpr bool is_optional = true;
	static constexpr bool has_default = true;
};

template<typename SpecOptions>
struct any_traits<spec::any<SpecOptions>> final
{
	static constexpr bool is_any = true;
};

template<typename SpecOptions>
struct extension_traits<spec::extension_marker<SpecOptions>> final
{
	static constexpr bool is_extension_marker = true;
};
} //namespace detail
} //namespace asn1
