// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <concepts>
#include <iterator>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

#include <boost/pfr/core.hpp>

#include "simple_asn1/decode.h"
#include "simple_asn1/spec.h"
#include "simple_asn1/types.h"

namespace asn1::detail::der
{
template<typename DecodeState, auto Throw = default_throw>
std::pair<tag_type, length_type> decode_type_length(
	DecodeState& state)
{
	static constexpr bool is_random_access_iterator
		= RandomAccessIterator<decltype(state.begin)>;
	if constexpr (is_random_access_iterator)
	{
		if (state.end - state.begin < 2)
			Throw("No tag and length");
	}
	else
	{
		if (state.begin == state.end)
			Throw("No tag and length");
	}

	auto tag = static_cast<tag_type>(*state.begin++);
	if constexpr (!is_random_access_iterator)
	{
		if (state.begin == state.end)
			Throw("No tag and length");
	}

	length_type length = static_cast<std::uint8_t>(*state.begin++);
	if (length > 127u)
	{
		if (length == 0xffu)
			Throw("Invalid length");

		length = decode_integer<length_type,
			DecodeState, Throw>(length & 0x7fu, state);
	}

	return { tag, length };
}

template<typename Specs, typename DecodeState>
std::pair<tag_type, length_type> decode_type_length_with_context(
	DecodeState& state)
{
	return decode_type_length<DecodeState, ([](const auto& message) {
		error_helper<Specs>::throw_with_context(message);
	})>(state);
}

template<typename DecodeState, typename Options,
	typename ParentContexts, typename Spec, typename Value>
struct der_decoder
{
	static constexpr bool can_decode(tag_type)
	{
		static_assert(std::is_same_v<Value, void>,
			"Unsupported tag or corresponding value type");
		return false;
	}

	static constexpr void decode_explicit(Value&,
		const DecodeState&, length_type)
	{
		static_assert(std::is_same_v<Value, void>,
			"Unsupported tag or corresponding value type");
	}

	static constexpr void decode_implicit(length_type,
		Value&, const DecodeState&)
	{
		static_assert(std::is_same_v<Value, void>,
			"Unsupported tag or corresponding value type");
	}
};

template<typename DecodeState, typename Options,
	typename ParentContexts, typename Spec, typename Value>
struct select_nested_der_decoder
	: der_decoder<DecodeState, Options, ParentContexts, Spec, Value> {};

template<typename DecodeState, typename Options,
	typename ParentContexts, typename Spec, typename Iterator, typename Value>
struct select_nested_der_decoder<DecodeState, Options, ParentContexts, Spec,
	with_offset<Iterator, Value>>
{
	using base_der_decoder_type = select_nested_der_decoder<DecodeState, Options, ParentContexts, Spec,
		Value>;
	using with_offset_value_type = with_offset<Iterator, Value>;

	static constexpr bool can_decode(tag_type tag)
	{
		return base_der_decoder_type::can_decode(tag);
	}

	static constexpr void decode_explicit(with_offset_value_type& value,
		const DecodeState& state, length_type length)
	{
		value.begin = state.begin;
		base_der_decoder_type::decode_explicit(value.value, state, length);
		value.end = state.begin;
	}

	static constexpr void decode_implicit(length_type length,
		with_offset_value_type& value, const DecodeState& state)
	{
		value.begin = state.begin;
		base_der_decoder_type::decode_implicit(length, value.value, state);
		value.end = state.begin;
	}
};

template<typename Decoder>
struct der_decoder_base final {};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename Spec, typename Value>
struct der_decoder_base<der_decoder<DecodeState, Options, ParentContexts, Spec, Value>>
{
	using decoder_impl_type = der_decoder<DecodeState, Options, ParentContexts, Spec, Value>;
	
	[[nodiscard]]
	static constexpr bool can_decode(tag_type target_tag) noexcept
	{
		constexpr tag_type tag = Spec::tag();
		return tag == target_tag;
	}

	static void decode_explicit(Value& value,
		DecodeState& state, length_type max_length)
	{
		decode_implicit(decode_length(
			state, max_length, decoder_impl_type::length_decode_error_text),
			value, state);
	}

	static void decode_implicit(length_type len, Value& value,
		DecodeState& state)
	{
		decoder_impl_type::decode_implicit_impl(len, value, state);
		try_validate_value<Options, ParentContexts, Spec>(value);
	}

	static length_type decode_length(DecodeState& state,
		length_type max_length, const char* tag_error_text)
	{
		using merged_specs = typename Options
			::template merge_spec_names<ParentContexts, Spec>;
		auto [tag, len] = decode_type_length_with_context<merged_specs>(state);
		if (!can_decode(tag))
		{
			error_helper<merged_specs>
				::throw_with_context(tag_error_text);
		}
		if (len > max_length)
		{
			error_helper<merged_specs>
				::throw_with_context("Length is too big and overruns buffer");
		}
		return len;
	}
};

//Non-decoded integer
template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, RangeAssignable<DecodeState> Value>
struct der_decoder<DecodeState, Options, ParentContexts, spec::integer<SpecOptions>, Value>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::integer<SpecOptions>, Value>>
{
	static constexpr const char* length_decode_error_text = "Expected INTEGER";
	
	static void decode_implicit_impl(length_type len, Value& value,
		DecodeState& state)
	{
		value = Value{ state.begin, state.begin + len };
		state.begin += len;
	}
};

//Decoded integer
template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, std::signed_integral Value>
struct der_decoder<DecodeState, Options, ParentContexts, spec::integer<SpecOptions>, Value>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::integer<SpecOptions>, Value>>
{
	static constexpr const char* length_decode_error_text = "Expected INTEGER";

	static void decode_implicit_impl(length_type len, Value& value,
		DecodeState& state)
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, spec::integer<SpecOptions>>;
		value = decode_integer_with_context<Value, merged_specs>(len, state);
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, Enumerated Value>
struct der_decoder<DecodeState, Options, ParentContexts, spec::enumerated<SpecOptions>, Value>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::enumerated<SpecOptions>, Value>>
{
	static constexpr const char* length_decode_error_text = "Expected ENUMERATED";

	static void decode_implicit_impl(length_type len, Value& value,
		DecodeState& state)
	{
		using base_enum_type = typename std::conditional_t<std::is_enum_v<Value>,
			std::underlying_type<Value>, std::type_identity<Value>>::type;
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, spec::enumerated<SpecOptions>>;
		value = static_cast<Value>(decode_integer_with_context<
			base_enum_type, merged_specs>(len, state));
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts, spec::boolean<SpecOptions>, bool>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::boolean<SpecOptions>, bool>>
{
	static constexpr const char* length_decode_error_text = "Expected BOOLEAN";

	static void decode_implicit_impl(length_type len, bool& value,
		DecodeState& state)
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, spec::boolean<SpecOptions>>;
		auto result = decode_integer_with_context<std::uint8_t,
			merged_specs>(len, state);
		if (result == 0xffu)
		{
			value = true;
		}
		else if (result == 0u)
		{
			value = false;
		}
		else
		{
			error_helper<merged_specs>
				::throw_with_context("Invalid BOOLEAN value");
		}
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts, spec::null<SpecOptions>, std::nullptr_t>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::null<SpecOptions>, std::nullptr_t>>
{
	static constexpr const char* length_decode_error_text = "Expected NULL";

	static void decode_implicit_impl(length_type len, std::nullptr_t& value,
		DecodeState&)
	{
		if (len)
		{
			using merged_specs = typename Options::template
				merge_spec_names<ParentContexts, spec::null<SpecOptions>>;
			error_helper<merged_specs>
				::throw_with_context("Invalid NULL length");
		}
		value = nullptr;
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, std::uint8_t Tag, spec::encoding Encoding,
	spec::cls Class, typename SpecOptions, typename Spec, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::tagged_with_options<Tag, Encoding, Class, SpecOptions, Spec>, Value>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::tagged_with_options<Tag, Encoding, Class, SpecOptions, Spec>, Value>>
{
	static constexpr const char* length_decode_error_text = "Expected tagged";

	using merged_specs = typename Options::template
		merge_spec_names<ParentContexts,
			spec::tagged_with_options<Tag, Encoding, Class, SpecOptions, Spec>>;
	using nested_decoder_type = select_nested_der_decoder<DecodeState, Options, merged_specs,
		Spec, Value>;

	static void decode_implicit_impl(length_type len, Value& value,
		DecodeState& state)
	{
		if constexpr (Encoding == spec::encoding::expl)
			nested_decoder_type::decode_explicit(value, state, len);
		else
			nested_decoder_type::decode_implicit(len, value, state);
	}
};

template<typename DecodeState, typename Options,
	typename ParentContexts, typename SpecOptions, RangeAssignable<DecodeState> Value>
struct der_decoder<DecodeState, Options, ParentContexts, spec::any<SpecOptions>, Value>
{
	[[nodiscard]]
	static constexpr bool can_decode(std::uint8_t /* target_tag */) noexcept
	{
		return true;
	}

	static void decode_explicit(Value& value, DecodeState& state,
		length_type max_length)
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, spec::any<SpecOptions>>;
		auto begin = state.begin;
		auto [tag, len] = decode_type_length_with_context<merged_specs>(state);
		if (len > max_length)
		{
			error_helper<merged_specs>
				::throw_with_context("Length is too big and overruns buffer");
		}

		len += state.begin - begin;
		state.begin = begin;

		decode_implicit(len, value, state);
	}

	static void decode_implicit(length_type len, Value& value,
		DecodeState& state)
	{
		value = Value{ state.begin, state.begin + len };
		state.begin += len;
		try_validate_value<Options, ParentContexts,
			spec::any<SpecOptions>>(value);
	}
};

template<typename DecodeState, typename ParentContexts,
	typename Options, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::extension_marker<SpecOptions>, extension_sentinel>
{
	[[nodiscard]]
	static constexpr bool can_decode(std::uint8_t /* target_tag */) noexcept
	{
		return true;
	}

	static void decode_explicit(extension_sentinel&, DecodeState& state,
		length_type max_length)
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, spec::extension_marker<SpecOptions>>;
		while (max_length)
		{
			auto begin = state.begin;
			auto [tag, len] = decode_type_length_with_context<merged_specs>(state);
			if (len > max_length)
			{
				error_helper<merged_specs>
					::throw_with_context("Length is too big and overruns buffer");
			}

			state.begin += len;
			max_length -= (state.begin - begin);
		}
	}

	template<typename Dummy>
	static void decode_implicit(length_type, Dummy&, DecodeState&)
	{
		static_assert(std::is_same_v<Dummy, sentinel>,
			"Sequence extension marker can not be decoded/tagged implicitly");
	}
};

template<typename DecodeState,
	typename Options, typename TypeByIndex, typename ParentContexts,
	typename... Specs>
struct unique_tags_decoder
{
public:
	//TODO: limit array size by the max tag value from the underlying types
	using child_decoder_list_type = std::array<
		typename TypeByIndex::template child_decoder_type<DecodeState>,
		(std::numeric_limits<tag_type>::max)()>;

private:
	static constexpr child_decoder_list_type collect_decoders() noexcept
	{
		constexpr auto result = collect_decoders_impl(
			std::index_sequence_for<Specs...>{});
		static_assert(result.second, "Duplicate tags in unique tags spec");
		return result.first;
	}

	template<std::size_t... Indexes>
	static constexpr std::pair<child_decoder_list_type, bool> collect_decoders_impl(
		std::index_sequence<Indexes...>) noexcept
	{
		std::pair<child_decoder_list_type, bool> result{ {}, true };
		(..., add_decoders<Specs, Indexes>(result.first, result.second));
		return result;
	}

	template<typename Spec, std::size_t Index>
	static constexpr void add_decoders(child_decoder_list_type& decoders, bool& valid) noexcept
	{
		using child_type = typename TypeByIndex::template type<Index>;
		using nested_decoder_type = select_nested_der_decoder<DecodeState, Options,
			ParentContexts, Spec, child_type>;
		constexpr auto child_decoder = TypeByIndex::template create_child_decoder<
			Options, DecodeState, nested_decoder_type, ParentContexts, Spec, Index>();
		if constexpr (!spec_traits<Spec>::is_choice)
		{
			constexpr bool is_any = any_traits<Spec>::is_any;
			static_assert(!is_any, "ANY inside unique tag spec is not supported");
			if constexpr (!is_any)
			{
				constexpr tag_type tag = Spec::tag();
				if (decoders[tag])
					valid = false;

				decoders[tag] = child_decoder;
			}
		}
		else
		{
			for (std::size_t i = 0;
				i != std::tuple_size_v<decltype(nested_decoder_type::contained_tag_list)>; ++i)
			{
				tag_type tag = nested_decoder_type::contained_tag_list[i];
				if (decoders[tag])
					valid = false;

				decoders[tag] = child_decoder;
			}
		}
	}

public:
	static constexpr child_decoder_list_type child_decoders{
		collect_decoders() };

	[[nodiscard]]
	static constexpr bool can_decode(tag_type target_tag) noexcept
	{
		return child_decoders[target_tag];
	}
};

template<typename Variant>
struct choice_type_by_index final
{
	template<typename DecodeState>
	using child_decoder_type = void(*)(tag_type, length_type, Variant&,
		DecodeState&);

	template<typename Options, typename DecodeState, typename NestedDecoderType,
		typename ParentContexts, typename Spec, std::size_t Index>
	[[nodiscard]]
	static constexpr child_decoder_type<DecodeState> create_child_decoder() noexcept
	{
		return []([[maybe_unused]] tag_type tag, length_type len,
			Variant& value, DecodeState& state) {
			if constexpr (spec_traits<Spec>::is_choice)
			{
				NestedDecoderType::decode_known_tag(
					tag, len, value.template emplace<Index>(), state);
			}
			else
			{
				NestedDecoderType::decode_implicit(
					len, value.template emplace<Index>(), state);
			}
		};
	}

	template<std::size_t Index>
	using type = std::variant_alternative_t<Index, Variant>;
};

template<typename DecodeState,
	typename Options, typename SpecOptions, typename ParentContexts,
	typename... Specs, typename... Values>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::choice_with_options<SpecOptions, Specs...>,
	std::variant<Values...>>
	: unique_tags_decoder<DecodeState, Options,
		choice_type_by_index<std::variant<Values...>>,
		typename Options::template merge_spec_names<
			ParentContexts, spec::choice_with_options<SpecOptions, Specs...>>,
		Specs...>
{
	using this_parent_specs = typename Options::template merge_spec_names<
		ParentContexts, spec::choice_with_options<SpecOptions, Specs...>>;
	using base_type = unique_tags_decoder<DecodeState, Options,
		choice_type_by_index<std::variant<Values...>>, this_parent_specs, Specs...>;

	static void decode_explicit(std::variant<Values...>& value,
		DecodeState& state, length_type max_length)
	{
		auto [tag, len] = decode_type_length_with_context<this_parent_specs>(state);
		if (len > max_length)
		{
			error_helper<this_parent_specs>
				::throw_with_context("Invalid CHOICE element length");
		}
		decode_known_tag(tag, len, value, state);
	}

	static void decode_known_tag(tag_type tag, length_type len,
		std::variant<Values...>& value, DecodeState& state)
	{
		auto child_decoder = base_type::child_decoders[tag];
		if (!child_decoder)
		{
			error_helper<this_parent_specs>
				::throw_with_context("Unable to decode CHOICE");
		}

		child_decoder(tag, len, value, state);
		try_validate_value<Options, ParentContexts,
			spec::choice_with_options<SpecOptions, Specs...>>(value);
	}

	template<typename Dummy>
	static void decode_implicit(length_type, Dummy&, DecodeState&)
	{
		static_assert(std::is_same_v<Dummy, sentinel>,
			"CHOICE can not be decoded/tagged implicitly");
	}

private:
	static constexpr std::size_t count_contained_tags() noexcept
	{
		std::size_t result = 0;
		for (auto decoder : base_type::child_decoders)
		{
			if (decoder)
				++result;
		}
		return result;
	}

	static constexpr auto create_contained_tag_list() noexcept
	{
		constexpr auto tag_count = count_contained_tags();
		std::array<tag_type, tag_count> result{};
		std::size_t i = 0;
		for (std::size_t decoder_index = 0;
			decoder_index != base_type::child_decoders.size(); ++decoder_index)
		{
			if (base_type::child_decoders[decoder_index])
				result[i++] = static_cast<tag_type>(decoder_index);
		}
		return result;
	}

public:
	static constexpr auto contained_tag_list{ create_contained_tag_list() };
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename Spec, OptionalType Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::optional<Spec>, Value>
	: der_decoder<DecodeState, Options, ParentContexts, Spec, typename ptr_traits<Value>::type>
{
	using nested_decoder_type = select_nested_der_decoder<
		DecodeState, Options, ParentContexts, Spec, typename ptr_traits<Value>::type>;

	static void decode_explicit(Value& value,
		DecodeState& state, length_type max_length)
	{
		auto& nested_value = ptr_traits<Value>::make(value);
		nested_decoder_type::decode_explicit(
			nested_value, state, max_length);
		try_validate_value<Options, ParentContexts,
			spec::optional<Spec>>(nested_value);
	}

	static void decode_implicit(length_type len, Value& value,
		DecodeState& state)
	{
		auto& nested_value = ptr_traits<Value>::make(value);
		nested_decoder_type::decode_implicit(len, nested_value, state);
		try_validate_value<Options, ParentContexts,
			spec::optional<Spec>>(nested_value);
	}

	static void decode_known_tag(tag_type tag, length_type len,
		Value& value, DecodeState& state)
		requires (spec_traits<Spec>::is_choice)
	{
		auto& nested_value = ptr_traits<Value>::make(value);
		nested_decoder_type::decode_known_tag(tag, len,
			nested_value, state);
		try_validate_value<Options, ParentContexts,
			spec::optional<Spec>>(nested_value);
	}
};

template<typename DecodeState,
	typename Options, typename DefaultValueProvider,
	typename ParentContexts, typename Spec, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::optional_default<DefaultValueProvider, Spec>, Value>
	: der_decoder<DecodeState, Options, ParentContexts, Spec, Value>
{
	using nested_decoder_type = select_nested_der_decoder<
		DecodeState, Options, ParentContexts, Spec, Value>;

	static void decode_explicit(Value& value,
		DecodeState& state, length_type max_length)
	{
		nested_decoder_type::decode_explicit(value, state, max_length);
		try_validate_value<Options, ParentContexts,
			spec::optional_default<DefaultValueProvider, Spec>>(value);
	}
	
	static void decode_implicit(length_type len, Value& value,
		DecodeState& state)
	{
		nested_decoder_type::decode_implicit(len, value, state);
		try_validate_value<Options, ParentContexts,
			spec::optional_default<DefaultValueProvider, Spec>>(value);
	}

	static void decode_known_tag(tag_type tag, length_type len,
		Value& value, DecodeState& state)
		requires (spec_traits<Spec>::is_choice)
	{
		nested_decoder_type::decode_known_tag(tag, len,
			value, state);
		try_validate_value<Options, ParentContexts,
			spec::optional_default<DefaultValueProvider, Spec>>(value);
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions,
	typename... Specs, SequenceType Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::sequence_with_options<SpecOptions, Specs...>, Value>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::sequence_with_options<SpecOptions, Specs...>, Value>>
{
	static constexpr const char* length_decode_error_text = "Expected SEQUENCE";

	using this_parent_spec = typename Options::template merge_spec_names<ParentContexts,
		spec::sequence_with_options<SpecOptions, Specs...>>;

	static void decode_implicit_impl(length_type len,
		Value& value, DecodeState& state)
	{
		static_assert(boost::pfr::tuple_size_v<Value> == sizeof...(Specs),
			"Value structure must have the same amount of fields"
			" as the number of nested SEQUENCE specifications");
		if (!decode_field<0, sizeof...(Specs), Specs...>(len, value, state))
		{
			error_helper<this_parent_spec>
				::throw_with_context("SEQUENCE data is not fully consumed");
		}
	}

private:
	template<std::size_t Index, std::size_t MaxIndex,
		typename Spec, typename... RemainingSpecs>
	static std::size_t decode_field(length_type len,
		Value& value, DecodeState& state)
	{
		auto& field = boost::pfr::get<Index>(value);
		using optional_traits_type = optional_traits<Spec>;
		using nested_decoder_type = select_nested_der_decoder<DecodeState, Options,
			this_parent_spec, Spec, std::remove_cvref_t<decltype(field)>>;
		using merged_specs = typename Options::template
			merge_spec_names<this_parent_spec, Spec>;
		if (!len)
		{
			if constexpr (extension_traits<Spec>::is_extension_marker)
			{
				nested_decoder_type::decode_explicit(field, state, len);
			}
			else if constexpr (!optional_traits_type::is_optional)
			{
				error_helper<merged_specs>
					::throw_with_context("Unable to decode SEQUENCE required member, no data left");
			}
			else if constexpr (optional_traits_type::has_default)
			{
				Spec::assign_default(field);
			}
		}
		else
		{
			auto tag = static_cast<tag_type>(*state.begin);
			if (nested_decoder_type::can_decode(tag))
			{
				auto begin = state.begin;
				nested_decoder_type::decode_explicit(field, state, len);
				len -= state.begin - begin;
			}
			else
			{
				if constexpr (!optional_traits_type::is_optional)
				{
					error_helper<merged_specs>
						::throw_with_context("Non-matching nested SEQUENCE type");
				}
				else if constexpr (optional_traits_type::has_default)
				{
					Spec::assign_default(field);
				}
			}
		}

		if constexpr (Index + 1 != MaxIndex)
			return decode_field<Index + 1, MaxIndex, RemainingSpecs...>(len, value, state);
		else
			return len == 0u;
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, template<typename, typename> typename SequenceOf,
	typename Spec, typename SpecOptions, SequentialContainer Value>
struct sequence_of_der_decoder
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, SequenceOf<SpecOptions, Spec>, Value>>
{
	using nested_decoder_type = select_nested_der_decoder<DecodeState, Options,
		typename Options::template merge_spec_names<ParentContexts, SequenceOf<SpecOptions, Spec>>,
		Spec, typename Value::value_type>;
	using merged_specs = typename Options::template
		merge_spec_names<ParentContexts, Spec>;

	static void decode_implicit_impl(length_type len,
		Value& value, DecodeState& state)
	{
		using min_max_elements_option_type = typename SequenceOf<SpecOptions, Spec>
			::template option_by_category<option_cat::min_max_elements>;
		[[maybe_unused]] std::size_t element_count = 0;
		while (len)
		{
			if constexpr (!std::is_same_v<min_max_elements_option_type, void>)
			{
				if (++element_count > min_max_elements_option_type::max_elems)
				{
					error_helper<merged_specs>
						::throw_with_context("Too many elements");
				}
			}

			auto begin = state.begin;
			nested_decoder_type::decode_explicit(value.emplace_back(), state, len);
			len -= state.begin - begin;
		}

		if constexpr (!std::is_same_v<min_max_elements_option_type, void>)
		{
			if constexpr (min_max_elements_option_type::min_elems)
			{
				if (element_count < min_max_elements_option_type::min_elems)
				{
					error_helper<merged_specs>
						::throw_with_context("Too few elements");
				}
			}
		}
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts,
	typename SpecOptions, typename Spec, SequentialContainer Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::sequence_of_with_options<SpecOptions, Spec>, Value>
	: sequence_of_der_decoder<DecodeState, Options, ParentContexts,
		spec::sequence_of_with_options, Spec, SpecOptions, Value>
{
	static constexpr const char* length_decode_error_text = "Expected SEQUENCE OF";
};

template<typename DecodeState,
	typename Options, typename ParentContexts,
	typename SpecOptions, typename Spec, SequentialContainer Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::set_of_with_options<SpecOptions, Spec>, Value>
	: sequence_of_der_decoder<DecodeState, Options, ParentContexts,
			spec::set_of_with_options, Spec, SpecOptions, Value>
{
	static constexpr const char* length_decode_error_text = "Expected SET OF";
};

struct [[nodiscard]] marked_tags
{
private:
	using section_type = std::uint64_t;
	static constexpr auto section_digits
		= std::numeric_limits<std::uint64_t>::digits;

public:
	[[nodiscard]]
	bool mark(tag_type tag) noexcept
	{
		auto& section = marked_[tag / section_digits];
		auto bit = 1ull << (tag % section_digits);
		if (section & bit)
			return false;

		section |= bit;
		return true;
	}

	[[nodiscard]]
	constexpr bool is_marked(tag_type tag) const noexcept
	{
		auto section = marked_[tag / section_digits];
		auto bit = 1ull << (tag % section_digits);
		return static_cast<bool>(section & bit);
	}

private:
	std::array<section_type, std::numeric_limits<tag_type>::max()
		/ section_digits> marked_{};
};

template<typename Value>
struct set_type_by_index final
{
	template<typename DecodeState>
	using child_decoder_type = void(*)(tag_type, length_type,
		marked_tags&, std::size_t&, Value&, DecodeState&);

	template<typename Options, typename DecodeState, typename NestedDecoderType,
		typename ParentContexts, typename Spec, std::size_t Index>
	static constexpr child_decoder_type<DecodeState> create_child_decoder() noexcept
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, Spec>;
		return []([[maybe_unused]] tag_type tag, length_type len,
			marked_tags& decoded_tags, std::size_t& required_count, Value& value,
			DecodeState& state) {
			if constexpr (!optional_traits<Spec>::is_optional)
				++required_count;

			if constexpr (spec_traits<Spec>::is_choice)
			{
				for (tag_type child_tag : NestedDecoderType::contained_tag_list)
				{
					if (!decoded_tags.mark(child_tag))
					{
						error_helper<merged_specs>
							::throw_with_context("Encountered duplicate SET elements");
					}
				}

				NestedDecoderType::decode_known_tag(
					tag, len, boost::pfr::get<Index>(value), state);
			}
			else
			{
				if (!decoded_tags.mark(tag))
				{
					error_helper<merged_specs>
						::throw_with_context("Encountered duplicate SET elements");
				}

				NestedDecoderType::decode_implicit(
					len, boost::pfr::get<Index>(value), state);
			}
		};
	}

	template<std::size_t Index>
	using type = boost::pfr::tuple_element_t<Index, Value>;
};

template<typename DecodeState,
	typename Options, typename ParentContexts,
	typename SpecOptions, typename... Specs, SequenceType Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::set_with_options<SpecOptions, Specs...>, Value>
	: unique_tags_decoder<DecodeState, Options,
		set_type_by_index<Value>, ParentContexts, Specs...>
{
	using this_parent_specs = typename Options::template merge_spec_names<ParentContexts,
		spec::set_with_options<SpecOptions, Specs...>>;

	static constexpr const char* length_decode_error_text = "Expected SET";
	
	using base_type = unique_tags_decoder<DecodeState, Options,
		set_type_by_index<Value>, this_parent_specs, Specs...>;

	static void decode_explicit(Value& value,
		DecodeState& state, length_type max_length)
	{
		using explicit_decoder_type = der_decoder_base<der_decoder<DecodeState,
			Options, ParentContexts, spec::set_with_options<SpecOptions, Specs...>, Value>>;
		explicit_decoder_type::decode_explicit(value, state, max_length);
	}

	static void decode_implicit(length_type len,
		Value& value, DecodeState& state)
	{
		decode_implicit_impl(len, value, state);
		try_validate_value<Options, ParentContexts,
			spec::set_with_options<SpecOptions, Specs...>>(value);
	}

	static void decode_implicit_impl(length_type len,
		Value& value, DecodeState& state)
	{
		static_assert(boost::pfr::tuple_size_v<Value> == sizeof...(Specs),
			"Value structure must have the same amount of fields"
			" as the number of nested SET specifications");

		marked_tags decoded_tags;
		std::size_t decoded_required_count{};
		while (len)
		{
			auto begin = state.begin;
			auto [tag, child_len] = decode_type_length_with_context<
				this_parent_specs>(state);

			if (child_len > len)
			{
				error_helper<this_parent_specs>
					::throw_with_context("Invalid SET element length");
			}

			auto child_decoder = base_type::child_decoders[tag];
			if (!child_decoder)
			{
				error_helper<this_parent_specs>
					::throw_with_context("Unable to decode SET element");
			}

			child_decoder(tag, child_len, decoded_tags,
				decoded_required_count, value, state);
			len -= state.begin - begin;
		}

		static constexpr auto required_field_count = (... + static_cast<std::size_t>(
			!optional_traits<Specs>::is_optional));
		if (decoded_required_count != required_field_count)
		{
			error_helper<this_parent_specs>
				::throw_with_context("Missing required SET elements");
		}

		initialize_defaults(value, decoded_tags,
			std::index_sequence_for<Specs...>{});
	}

private:
	template<std::size_t... Index>
	static void initialize_defaults(Value& value, const marked_tags& decoded_tags,
		std::index_sequence<Index...>)
	{
		(..., initialize_default<Specs, Index>(value, decoded_tags));
	}

	template<typename Spec, std::size_t Index>
	static void initialize_default(Value& value, const marked_tags& decoded_tags)
	{
		if constexpr (optional_traits<Spec>::has_default)
		{
			if constexpr (spec_traits<Spec>::is_choice)
			{
				using child_type = boost::pfr::tuple_element_t<Index, Value>;
				using nested_decoder_type = select_nested_der_decoder<DecodeState, Options,
					this_parent_specs, Spec, child_type>;
				if (!decoded_tags.is_marked(nested_decoder_type::contained_tag_list[0]))
					Spec::assign_default(boost::pfr::get<Index>(value));
			}
			else
			{
				static constexpr tag_type tag = Spec::tag();
				if (!decoded_tags.is_marked(tag))
					Spec::assign_default(boost::pfr::get<Index>(value));
			}
		}
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions,
	RangeAssignable<DecodeState> Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::octet_string<SpecOptions>, Value>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::octet_string<SpecOptions>, Value>>
{
	static constexpr const char* length_decode_error_text = "Expected OCTET STRING";

	static void decode_implicit_impl(length_type len, Value& value,
		DecodeState& state)
	{
		value = Value{ state.begin, state.begin + len };
		state.begin += len;
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions,
	RangeAssignable<DecodeState> Container>
struct der_decoder<DecodeState, Options, ParentContexts, spec::bit_string<SpecOptions>,
	bit_string<Container>>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::bit_string<SpecOptions>, bit_string<Container>>>
{
	static constexpr const char* length_decode_error_text = "Expected BIT STRING";

	static void decode_implicit_impl(length_type len, bit_string<Container>& value,
		DecodeState& state)
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, spec::bit_string<SpecOptions>>;
		if (!len)
		{
			error_helper<merged_specs>
				::throw_with_context("Empty BIT STRING value");
		}

		std::uint8_t unused_bits = static_cast<std::uint8_t>(*state.begin++);
		--len;

		value.bit_count = len * std::numeric_limits<std::uint8_t>::digits;
		if (unused_bits > value.bit_count)
		{
			error_helper<merged_specs>
				::throw_with_context("Too many BIT STRING unused bits");
		}

		value.bit_count -= unused_bits;
		value.container = Container{ state.begin, state.begin + len };
		state.begin += len;
	}
};

template<typename Options, typename DecodeState, typename ParentContexts,
	typename Spec, typename Container, bool IsRelative>
struct oid_decoder
{
	static void decode_implicit_impl(length_type len, Container& value,
		DecodeState& state)
	{
		value = Container{ state.begin, state.begin + len };
		state.begin += len;
	}
};

template<typename Options, typename DecodeState, typename ParentContexts,
	typename Spec, typename Container, bool IsRelative>
struct oid_decoder<Options, DecodeState, ParentContexts, Spec,
	decoded_object_identifier<Container>, IsRelative>
{
	static void decode_implicit_impl(length_type len,
		decoded_object_identifier<Container>& value,
		DecodeState& state)
	{
		using merged_specs = typename Options::template
			merge_spec_names<ParentContexts, Spec>;
		value.container = decode_oid<Container, IsRelative, DecodeState,
			([](const auto& message) {
			error_helper<merged_specs>::throw_with_context(message);
		})>(len, state);
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, Oid<DecodeState> Container>
struct der_decoder<DecodeState, Options, ParentContexts,
		spec::object_identifier<SpecOptions>, Container>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::object_identifier<SpecOptions>, Container>>
	, oid_decoder<Options, DecodeState, ParentContexts,
		spec::object_identifier<SpecOptions>, Container, false>
{
	static constexpr const char* length_decode_error_text = "Expected OBJECT IDENTIFIER";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, Oid<DecodeState> Container>
struct der_decoder<DecodeState, Options, ParentContexts,
		spec::relative_oid<SpecOptions>, Container>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::relative_oid<SpecOptions>, Container>>
	, oid_decoder<Options, DecodeState,
		ParentContexts, spec::relative_oid<SpecOptions>, Container, true>
{
	static constexpr const char* length_decode_error_text = "Expected RELATIVE-OID";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, template<typename> typename StringSpec,
	typename SpecOptions, typename Char, typename Value>
struct string_decoder final
{
	static_assert(std::is_same_v<Value, void>, "Invalid string decoder arguments");
};

template<typename DecodeState,
	typename Options, typename ParentContexts, template<typename> typename StringSpec,
	typename SpecOptions, typename Char, RangeAssignable<DecodeState> Value>
struct string_decoder<DecodeState, Options, ParentContexts,
	StringSpec, SpecOptions, Char, Value>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		StringSpec<SpecOptions>, Value>>
{
	static void decode_implicit_impl(length_type len, Value& value,
		DecodeState& state)
	{
		if constexpr (sizeof(Char) > 1u)
		{
			using merged_specs = typename Options::template
				merge_spec_names<ParentContexts, StringSpec<SpecOptions>>;
			if (len % sizeof(Char))
			{
				error_helper<merged_specs>
					::throw_with_context("Invalid string length");
			}
		}

		value = Value{ state.begin, state.begin + len };
		state.begin += len;
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, template<typename> typename StringSpec,
	typename SpecOptions, typename Char, typename OtherChar,
	typename Traits, typename Allocator>
struct string_decoder<DecodeState, Options, ParentContexts, StringSpec, SpecOptions, Char,
	std::basic_string<OtherChar, Traits, Allocator>>
	: der_decoder<DecodeState, sentinel, ParentContexts, sentinel,
		std::basic_string<OtherChar, Traits, Allocator>>
{
};

template<typename DecodeState,
	typename Options, typename ParentContexts, template<typename> typename StringSpec,
	typename SpecOptions, typename Char, typename Traits, typename Allocator>
struct string_decoder<DecodeState, Options, ParentContexts, StringSpec, SpecOptions, Char,
	std::basic_string<Char, Traits, Allocator>>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		StringSpec<SpecOptions>, std::basic_string<Char, Traits, Allocator>>>
{
	static void decode_implicit_impl(length_type len,
		std::basic_string<Char, Traits, Allocator>& value,
		DecodeState& state)
	{
		if constexpr (sizeof(Char) > 1u)
		{
			using merged_specs = typename Options::template
				merge_spec_names<ParentContexts, StringSpec<SpecOptions>>;
			if (len % sizeof(Char))
			{
				error_helper<merged_specs>
					::throw_with_context("Invalid string length");
			}
		}

		value.resize(static_cast<std::size_t>(len / sizeof(Char)));
		auto ptr = value.data();
		if constexpr (sizeof(Char) == 1u)
		{
			while (len--)
			{
				*ptr++ = static_cast<Char>(*state.begin++);
			}
		}
		else
		{
			while (len)
			{
				std::make_unsigned_t<Char> char_value{};
				for (std::size_t i = 0; i != sizeof(Char); ++i)
				{
					if constexpr (sizeof(Char) > 1u)
						char_value <<= 8u;
					char_value |= static_cast<decltype(char_value)>(*state.begin++);
				}
				*ptr++ = static_cast<Char>(char_value);
				len -= sizeof(Char);
			}
		}
	}
};

//Allow UTF-8 string to be decoded as both std::u8string and std::string
template<typename DecodeState,
	typename Options, typename ParentContexts,
	typename SpecOptions, typename Traits, typename Allocator>
struct string_decoder<DecodeState, Options, ParentContexts,
		spec::utf8_string, SpecOptions, char8_t,
		std::basic_string<char, Traits, Allocator>>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::utf8_string, SpecOptions, char,
		std::basic_string<char, Traits, Allocator>>
{
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::numeric_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::numeric_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected NumericString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::printable_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::printable_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected PrintableString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::ia5_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::ia5_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected IA5String";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::teletex_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::teletex_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected TeletexString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::videotex_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::videotex_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected VideotexString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::visible_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::visible_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected VisibleString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::graphic_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::graphic_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected GraphicString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::general_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::general_string, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected GeneralString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::object_descriptor<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::object_descriptor, SpecOptions, char, Value>
{
	static constexpr const char* length_decode_error_text = "Expected ObjectDescriptor";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::universal_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::universal_string, SpecOptions, char32_t, Value>
{
	static constexpr const char* length_decode_error_text = "Expected UniversalString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::bmp_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::bmp_string, SpecOptions, char16_t, Value>
{
	static constexpr const char* length_decode_error_text = "Expected BMPString";
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts,
	spec::utf8_string<SpecOptions>, Value>
	: string_decoder<DecodeState, Options, ParentContexts,
		spec::utf8_string, SpecOptions, char8_t, Value>
{
	static constexpr const char* length_decode_error_text = "Expected UTF8String";
};

template<typename Spec, std::size_t YearSize,
	typename DateTime, typename State>
void parse_date_time(DateTime& value, State& state)
{
	string_to_integer<YearSize, Spec>(value.year, state);
	string_to_integer<2u, Spec>(value.month, state);
	string_to_integer<2u, Spec>(value.day, state);
	string_to_integer<2u, Spec>(value.hour, state);
	string_to_integer<2u, Spec>(value.minute, state);
	string_to_integer<2u, Spec>(value.second, state);
}

template<typename Spec, typename State, typename DateTime>
void validate_suffix_and_date_time(std::uint16_t full_year,
	const DateTime& value, State& state)
{
	if (static_cast<char>(*state.begin++) != 'Z')
	{
		error_helper<Spec>
			::throw_with_context("Datetime lacks 'Z' postfix");
	}

	if (value.month < 1 || value.month > 12)
	{
		error_helper<Spec>
			::throw_with_context("Invalid datetime month value");
	}

	if (value.hour > 23)
	{
		error_helper<Spec>
			::throw_with_context("Invalid datetime hour value");
	}

	if (value.minute > 59)
	{
		error_helper<Spec>
			::throw_with_context("Invalid datetime minute value");
	}

	if (value.second > 59)
	{
		error_helper<Spec>
			::throw_with_context("Invalid datetime second value");
	}

	if (value.day < 1)
	{
		error_helper<Spec>
			::throw_with_context("Invalid datetime day value");
	}
	
	if (value.day > days_in_month[value.month])
	{
		if (value.day == 29u && value.month == 2u)
		{
			if (!full_year)
				return;

			bool is_leap_year = (full_year % 4u == 0u
				&& full_year % 100u != 0u) || (full_year % 400u == 0u);
			if (is_leap_year)
				return;
		}

		error_helper<Spec>
			::throw_with_context("Invalid datetime day value");
	}
}

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts, spec::generalized_time<SpecOptions>,
	generalized_time>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::generalized_time<SpecOptions>, generalized_time>>
{
	using this_parent_specs = typename Options::template merge_spec_names<
		ParentContexts, spec::generalized_time<SpecOptions>>;

	static constexpr const char* length_decode_error_text = "Expected GeneralizedTime";

	static void decode_implicit_impl(length_type len, generalized_time& value,
		DecodeState& state)
	{
		if (len < 15u || len > 35u)
		{
			error_helper<this_parent_specs>
				::throw_with_context("Invalid GeneralizedTime length");
		}

		auto begin = state.begin;
		parse_date_time<this_parent_specs, 4u>(value, state);
		if (static_cast<char>(*state.begin) == '.')
		{
			++state.begin;
			len -= state.begin - begin;
			if (len < 2) //at least one fraction digit + 'Z' suffix
			{
				error_helper<this_parent_specs>
					::throw_with_context("Absent GeneralizedTime seconds fraction value");
			}
			--len;

			std::array<char, 20u> chars;
			for (length_type i = 0; i != len; ++i)
				chars[i] = static_cast<char>(*state.begin++);

			if (chars[len - 1] == '0')
			{
				error_helper<this_parent_specs>
					::throw_with_context(
						"GeneralizedTime seconds fraction value has trailing zeros");
			}

			auto rc = std::from_chars(chars.data(),
				chars.data() + len, value.seconds_fraction);
			if (rc.ec != std::errc{} || rc.ptr != chars.data() + len)
			{
				error_helper<this_parent_specs>
					::throw_with_context("Invalid GeneralizedTime seconds fraction value");
			}
		}

		validate_suffix_and_date_time<this_parent_specs>(value.year, value, state);
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts, spec::utc_time<SpecOptions>, utc_time>
	: der_decoder_base<der_decoder<DecodeState, Options, ParentContexts,
		spec::utc_time<SpecOptions>, utc_time>>
{
	using this_parent_specs = typename Options::template merge_spec_names<
		ParentContexts, spec::utc_time<SpecOptions>>;

	static constexpr const char* length_decode_error_text = "Expected UTCTime";

	static void decode_implicit_impl(length_type len, utc_time& value,
		DecodeState& state)
	{
		if (len != 13u)
		{
			error_helper<this_parent_specs>
				::throw_with_context("Invalid UTCTime length");
		}

		parse_date_time<this_parent_specs, 2u>(value, state);

		using zero_year_option_type = typename spec::utc_time<SpecOptions>
			::template option_by_category<option_cat::zero_year>;
		if constexpr (!std::is_same_v<zero_year_option_type, void>)
		{
			std::uint16_t full_year = value.year <= 50u
				? value.year + zero_year_option_type::value
				: value.year + zero_year_option_type::value - 100u;
			validate_suffix_and_date_time<
				this_parent_specs>(full_year, value, state);
		}
		else
		{
			validate_suffix_and_date_time<
				this_parent_specs>(0u, value, state);
		}
	}
};

template<typename DecodeState,
	typename Options, typename ParentContexts, RecursiveSpec RecursiveWrapper, typename Value>
struct der_decoder<DecodeState, Options, ParentContexts, RecursiveWrapper, Value>
{
	using first_spec_name = typename first_spec_name_helper<ParentContexts>::type;
	using spec_type = typename RecursiveWrapper::type;
	using decoder_impl_type = select_nested_der_decoder<DecodeState, Options, first_spec_name,
		spec_type, typename ptr_traits<Value>::type>;

	[[nodiscard]]
	static constexpr bool can_decode(tag_type target_tag) noexcept
	{
		return decoder_impl_type::can_decode(target_tag);
	}

	static constexpr auto& create_if_ptr(Value& value)
	{
		return ptr_traits<Value>::make(value);
	}

	static void decode_explicit(Value& value,
		DecodeState& state, length_type max_length)
	{
		do_with_recursion_depth(state, [&] {
			decoder_impl_type::decode_explicit(create_if_ptr(value), state, max_length);
		});
	}

	static void decode_implicit(length_type len, Value& value,
		DecodeState& state)
	{
		do_with_recursion_depth(state, [&] {
			decoder_impl_type::decode_implicit(len, create_if_ptr(value), state);
		});
	}

	template<typename Func>
	static void do_with_recursion_depth(DecodeState& state, const Func& func)
	{
		if constexpr (WithRecursionDepthLimit<DecodeState>)
		{
			if (!state.max_recursion_depth)
			{
				error_helper<merge_spec_names<first_spec_name, spec_type>>
					::throw_with_context("Too deep recursion");
			}
			--state.max_recursion_depth;
		}

		func();

		if constexpr (WithRecursionDepthLimit<DecodeState>)
			++state.max_recursion_depth;
	}
};
} //namespace asn1::detail::der

namespace asn1::der
{
template<typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(decode_state<BufferIterator, BufferIteratorEnd>& state, T& result)
{
	using decoder_type = detail::der::select_nested_der_decoder<decltype(state),
		DecodeOptions, asn1::detail::parent_context_list<>, Spec, T>;

	decoder_type::decode_explicit(result, state, std::distance(state.begin, state.end));
	return state.begin;
}

template<typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(BufferIterator begin, BufferIteratorEnd end, T& result)
{
	decode_state state(begin, end);
	return decode<Spec, DecodeOptions>(state, result);
}

template<typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(decode_state<BufferIterator, BufferIteratorEnd>& state, T& result)
{
	return decode<Spec, decode_options<>>(state, result);
}

template<typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(BufferIterator begin, BufferIteratorEnd end, T& result)
{
	return decode<Spec, decode_options<>>(begin, end, result);
}

template<typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(
	decode_state_with_recursion_depth_limit<BufferIterator, BufferIteratorEnd>& state,
	T& result)
{
	using decoder_type = detail::der::select_nested_der_decoder<decltype(state),
		DecodeOptions, asn1::detail::parent_context_list<>, Spec, T>;

	decoder_type::decode_explicit(result, state, std::distance(state.begin, state.end));
	return state.begin;
}

template<typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(std::size_t max_recursion_depth,
	BufferIterator begin, BufferIteratorEnd end, T& result)
{
	decode_state_with_recursion_depth_limit state(begin, end);
	state.max_recursion_depth = max_recursion_depth;
	return decode<Spec, DecodeOptions>(state, result);
}

template<typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(std::size_t max_recursion_depth,
	BufferIterator begin, BufferIteratorEnd end, T& result)
{
	return decode<Spec, decode_options<>>(
		max_recursion_depth, begin, end, result);
}

template<typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd, typename T>
BufferIterator decode(
	decode_state_with_recursion_depth_limit<BufferIterator, BufferIteratorEnd>& state,
	T& result)
{
	return decode<Spec, decode_options<>>(state, result);
}

template<typename T, typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(decode_state<BufferIterator, BufferIteratorEnd>& state)
{
	T result;
	if (state.end != decode<Spec, DecodeOptions>(state, result))
	{
		throw parse_error("Not all data was consumed by the parser",
			parse_error::context_type{});
	}
	return result;
}

template<typename T, typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(BufferIterator begin, BufferIteratorEnd end)
{
	decode_state state(begin, end);
	return decode<T, Spec, DecodeOptions>(state);
}

template<typename T, typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(BufferIterator begin, BufferIteratorEnd end)
{
	return decode<T, Spec, decode_options<>>(begin, end);
}

template<typename T, typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(decode_state<BufferIterator, BufferIteratorEnd>& state)
{
	return decode<T, Spec, decode_options<>>(state);
}

template<typename T, typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(
	decode_state_with_recursion_depth_limit<BufferIterator, BufferIteratorEnd>& state)
{
	T result;
	if (state.end != decode<Spec, DecodeOptions>(state, result))
	{
		throw parse_error("Not all data was consumed by the parser",
			parse_error::context_type{});
	}
	return result;
}

template<typename T, typename Spec,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(
	decode_state_with_recursion_depth_limit<BufferIterator, BufferIteratorEnd>& state)
{
	return decode<T, Spec, decode_options<>>(state);
}

template<typename T, typename Spec, typename DecodeOptions,
	std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(std::size_t max_recursion_depth,
	BufferIterator begin, BufferIteratorEnd end)
{
	decode_state_with_recursion_depth_limit state(begin, end);
	state.max_recursion_depth = max_recursion_depth;
	return decode<T, Spec, DecodeOptions>(state);
}

template<typename T, typename Spec, std::forward_iterator BufferIterator,
	std::sentinel_for<BufferIterator> BufferIteratorEnd>
[[nodiscard]] T decode(std::size_t max_recursion_depth,
	BufferIterator begin, BufferIteratorEnd end)
{
	return decode<T, Spec, decode_options<>>(max_recursion_depth, begin, end);
}
} //namespace asn1::der
