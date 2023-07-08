// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <string_view>
#include <utility>
#include <vector>

#include "simple_asn1/spec.h"

namespace asn1
{
struct spec_context_entry
{
	std::string_view spec_name;
	std::string_view spec_type;
};

class parse_error : public std::runtime_error
{
public:
	using context_type = std::vector<spec_context_entry>;

public:
	template<typename Text, typename Context>
	parse_error(const Text& str, Context&& context)
		: std::runtime_error(str)
		, context_(std::forward<Context>(context))
	{
	}

	[[nodiscard]]
	const context_type& get_context() const noexcept
	{
		return context_;
	}

private:
	context_type context_;
};

namespace detail
{
template<typename Spec>
static constexpr auto get_spec_name() noexcept
{
	using name_option_type = option_by_cat<Spec, option_cat::name>;
	if constexpr (!std::is_same_v<name_option_type, void>)
		return name_option_type::value;
	else
		return false;
}

template<compile_time_string SpecName, compile_time_string SpecType>
struct context_entry final
{
	static constexpr compile_time_string spec_name{ SpecName };
	static constexpr compile_time_string spec_type{ SpecType };
};

template<typename... Contexts>
struct parent_context_list {};

template<typename Specs, auto Str, compile_time_string SpecType>
struct merge_contexts {};

template<typename... Contexts, compile_time_string Str, compile_time_string SpecType>
struct merge_contexts<parent_context_list<Contexts...>, Str, SpecType>
{
	using type = parent_context_list<Contexts..., context_entry<Str, SpecType>>;
};

template<typename... Contexts, compile_time_string SpecType>
struct merge_contexts<parent_context_list<Contexts...>, false, SpecType>
{
	using type = parent_context_list<Contexts..., context_entry<"", SpecType>>;
};

template<typename ParentContexts, typename Spec, compile_time_string SpecType>
struct merge_specs_helper {};

template<typename... Contexts, typename Spec, compile_time_string SpecType>
struct merge_specs_helper<parent_context_list<Contexts...>, Spec, SpecType>
{
	using type = typename merge_contexts<parent_context_list<Contexts...>,
		get_spec_name<Spec>(), SpecType>::type;
};

template<typename ParentContexts, typename Spec>
using merge_spec_names = typename merge_specs_helper<
	ParentContexts, Spec, spec_name_by_spec<Spec>>::type;

template<typename T>
struct ptr_traits final : std::type_identity<T>
{
	static constexpr bool is_optional_type = false;

	static constexpr T& make(T& value) noexcept
	{
		return value;
	}
};

template<typename T, typename D>
struct ptr_traits<std::unique_ptr<T, D>> final : std::type_identity<T>
{
	static constexpr bool is_optional_type = true;

	static T& make(std::unique_ptr<T, D>& value)
	{
		value = std::make_unique<T>();
		return *value;
	}
};

template<typename T>
struct ptr_traits<std::shared_ptr<T>> final : std::type_identity<T>
{
	static constexpr bool is_optional_type = true;

	static T& make(std::shared_ptr<T>& value)
	{
		value = std::make_shared<T>();
		return *value;
	}
};

template<typename T>
struct ptr_traits<std::optional<T>> final : std::type_identity<T>
{
	static constexpr bool is_optional_type = true;

	static constexpr T& make(std::optional<T>& value)
	{
		return value.emplace();
	}
};

template<typename Specs>
struct first_spec_name_helper
{
	using type = parent_context_list<>;
};

template<typename Context, typename... Contexts>
struct first_spec_name_helper<parent_context_list<Context, Contexts...>>
{
	using type = parent_context_list<Context>;
};

struct sentinel final {};

template<typename Spec>
struct error_helper final {};

template<typename... Contexts>
struct error_helper<parent_context_list<Contexts...>> final
{
private:
	static parse_error::context_type get_context()
	{
		return parse_error::context_type{
			spec_context_entry{ Contexts::spec_name.str, Contexts::spec_type.str }... };
	}

public:
	template<typename Text>
	[[noreturn]]
	static void throw_with_context(Text&& str)
	{
		throw parse_error(std::forward<Text>(str), get_context());
	}

	template<typename Text>
	[[noreturn]]
	static void throw_with_context_nested(Text&& str)
	{
		std::throw_with_nested(parse_error(std::forward<Text>(str), get_context()));
	}
};

template<typename Options, typename ParentContexts,
	typename Spec, typename Value>
void try_validate_value(const Value& value)
{
	using validator_option_type = option_by_cat<Spec, option_cat::validator>;
	if constexpr (!std::is_same_v<validator_option_type, void>)
	{
		try
		{
			(typename validator_option_type::validator_type{})(value);
		}
		catch (...)
		{
			using merged_specs = typename Options
				::template merge_spec_names<ParentContexts, Spec>;
			error_helper<merged_specs>
				::throw_with_context_nested("Value validation error");
		}
	}
}

constexpr auto default_throw = [](const auto& message) {
	throw std::runtime_error(message);
};

template<typename It>
concept RandomAccessIterator = std::random_access_iterator<std::remove_cvref_t<It>>;

template<typename Value, typename DecodeState>
concept RangeAssignable = requires (Value& value, DecodeState& state) {
	value = Value{ state.begin, state.begin };
};

template<typename Value>
concept Enumerated = std::is_signed_v<Value>
	|| (std::is_enum_v<Value> && std::is_signed_v<std::underlying_type_t<Value>>);

template<typename Value>
concept OptionalType = ptr_traits<Value>::is_optional_type;

template<typename Value>
concept SequenceType = std::is_class_v<Value> && std::is_aggregate_v<Value>;

template<typename Value>
concept SequentialContainer = requires (Value& value) {
	value.emplace_back();
	value.pop_back();
	typename Value::value_type;
};

template<typename T>
struct is_decoded_oid : std::false_type {};
template<SequentialContainer T>
struct is_decoded_oid<decoded_object_identifier<T>> : std::true_type {};

template<typename Value, typename DecodeState>
concept Oid = RangeAssignable<Value, DecodeState> || is_decoded_oid<Value>::value;

using length_type = std::size_t;

template<std::unsigned_integral T, typename DecodeState, auto Throw = default_throw>
T decode_base128(length_type& length, DecodeState& state)
{
	if (!length)
		Throw("Invalid base128 integer length");

	static constexpr bool is_random_access_iterator
		= RandomAccessIterator<decltype(state.begin)>;
	if constexpr (is_random_access_iterator)
	{
		if (static_cast<length_type>(state.end - state.begin) < length)
			Throw("Invalid base128 integer length");
	}

	T result{};
	std::uint32_t read_bytes{};
	while (length && read_bytes < sizeof(T))
	{
		if constexpr (!is_random_access_iterator)
		{
			if (state.begin == state.end)
				Throw("Invalid base128 integer length");
		}

		auto value = static_cast<std::uint8_t>(*state.begin++);
		--length;
		++read_bytes;
		result <<= 7u;
		if (value & 0x80u)
		{
			result |= value & ~0x80u;
		}
		else
		{
			result |= value;
			return result;
		}
	}
	Throw("Invalid or too big base128 integer value");
	return result; //previous statement is noreturn, this never happens
}

template<typename T, bool IsRelative,
	typename DecodeState, auto Throw = default_throw>
T decode_oid(length_type length, DecodeState& state)
{
	if (!length)
		Throw("Invalid OID length");

	static constexpr bool is_random_access_iterator
		= RandomAccessIterator<decltype(state.begin)>;
	if constexpr (is_random_access_iterator)
	{
		if (static_cast<length_type>(state.end - state.begin) < length)
			Throw("Invalid OID length");
	}

	T result;
	using value_type = typename T::value_type;

	if constexpr (!IsRelative)
	{
		auto first_component = decode_base128<std::uint32_t,
			DecodeState, Throw>(length, state);
		if (first_component > 0x4fu)
		{
			result.emplace_back(static_cast<value_type>(2u));
			first_component -= 80u;
			if (first_component > (std::numeric_limits<value_type>::max)())
				Throw("Too large OID component value");
			result.emplace_back(static_cast<value_type>(first_component));
		}
		else
		{
			if (first_component / 40u > (std::numeric_limits<value_type>::max)())
				Throw("Too large OID component value");
			result.emplace_back(static_cast<value_type>(first_component / 40u));
			result.emplace_back(static_cast<value_type>(first_component % 40u));
		}
	}

	while (length)
	{
		result.emplace_back(decode_base128<value_type,
			DecodeState, Throw>(length, state));
	}
	return result;
}

template<std::integral T, typename DecodeState, auto Throw = default_throw>
T decode_integer(length_type length, DecodeState& state)
{
	std::make_unsigned_t<T> value{};
	if (length > sizeof(value))
		Throw("Too long integer (unsupported)");

	if (!length)
		Throw("Invalid integer length");

	static constexpr bool is_random_access_iterator
		= RandomAccessIterator<decltype(state.begin)>;
	if constexpr (is_random_access_iterator)
	{
		if (static_cast<length_type>(state.end - state.begin) < length)
			Throw("Invalid integer length");
	}

	for (length_type i = 0; i != length; ++i)
	{
		if constexpr (!is_random_access_iterator)
		{
			if (state.begin == state.end)
				Throw("Invalid integer length");
		}

		if constexpr (sizeof(value) > sizeof(std::uint8_t))
		{
			if (i)
				value <<= 8u;
		}
		value |= static_cast<std::uint8_t>(*state.begin++);
	}

	if constexpr (std::is_signed_v<T>)
	{
		if (length < sizeof(value))
		{
			if (value & ((1ull
				<< (length * std::numeric_limits<std::uint8_t>::digits - 1u))))
			{
				//Propagate negativeness
				for (length_type i = length; i != sizeof(value); ++i)
				{
					value |= 0xffull
						<< (i * std::numeric_limits<std::uint8_t>::digits);
				}
			}
		}
	}

	return static_cast<T>(value);
}

template<std::integral T, typename Specs, typename DecodeState>
T decode_integer_with_context(length_type length, DecodeState& state)
{
	return decode_integer<T, DecodeState, ([](const auto& message) {
		error_helper<Specs>::throw_with_context(message);
	})>(length, state);
}

template<length_type Length, typename Spec,
	typename T, typename DecodeState>
void string_to_integer(T& value, DecodeState& state)
{
	std::array<char, Length> temp;
	for (char& ch : temp)
		ch = static_cast<char>(*state.begin++);
	auto rc = std::from_chars(temp.data(), temp.data() + Length, value);
	if (rc.ec != std::errc{} || rc.ptr != temp.data() + Length)
		error_helper<Spec>::throw_with_context("Unable to parse integer");
}

constexpr std::array<std::uint8_t, 13u> days_in_month{
	0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

template<typename DecodeState>
concept WithRecursionDepthLimit = requires(DecodeState s) {
	{ s.max_recursion_depth } -> std::same_as<std::size_t&>;
};
} //namespace detail

namespace decode_opts
{
namespace error_context_policy
{
template<typename ParentContexts, typename Spec>
using full_context = detail::merge_spec_names<ParentContexts, Spec>;

template<typename ParentContexts, typename Spec>
using last_context = detail::merge_spec_names<detail::parent_context_list<>, Spec>;

template<typename ParentContexts, typename Spec>
using no_context = detail::parent_context_list<>;
} //namespace error_context_policy
} //namespace decode_opts

template<template <typename, typename> typename ExceptionContextPolicy
	= decode_opts::error_context_policy::full_context>
struct decode_options final
{
	template<typename ParentContexts, typename Spec>
	using merge_spec_names = ExceptionContextPolicy<ParentContexts, Spec>;
};

template<std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd = BufferIterator>
struct [[nodiscard]] decode_state
{
	using iterator_type = BufferIterator;
	using end_iterator_type = BufferIteratorEnd;

	explicit decode_state(BufferIterator begin, BufferIteratorEnd end)
		noexcept(noexcept(BufferIteratorEnd(end)))
		: begin(begin)
		, end(end)
	{
	}

	BufferIterator begin;
	BufferIteratorEnd end;
};

template<typename BufferIterator, typename BufferIteratorEnd>
decode_state(BufferIterator, BufferIteratorEnd)
	-> decode_state<BufferIterator, BufferIteratorEnd>;

template<std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd = BufferIterator>
struct [[nodiscard]] decode_state_with_recursion_depth_limit
	: decode_state<BufferIterator, BufferIteratorEnd>
{
	using decode_state<BufferIterator, BufferIteratorEnd>::decode_state;
	std::size_t max_recursion_depth = (std::numeric_limits<std::size_t>::max)();
};

template<typename BufferIterator, typename BufferIteratorEnd>
decode_state_with_recursion_depth_limit(BufferIterator, BufferIteratorEnd)
	-> decode_state_with_recursion_depth_limit<BufferIterator, BufferIteratorEnd>;
} //namespace asn1
