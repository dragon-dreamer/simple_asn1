// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <forward_list>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <stdexcept>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "simple_asn1/der_decode.h"
#include "simple_asn1/spec.h"
#include "simple_asn1/types.h"

#include "buffer_wrapper.h"

using namespace testing;

MATCHER_P(HasContext, value, "") {
	return std::find_if(arg.get_context().begin(), arg.get_context().end(),
	[&](const auto& entry) {
		return entry.spec_name == value;
	}) != arg.get_context().end();
}

MATCHER_P(HasExactContext, value, "") {
	std::stringstream ss;
	const char* delim = "";
	for (const auto& ctx : arg.get_context())
	{
		if (!ctx.spec_name.empty())
		{
			ss << delim;
			delim = "/";
			ss << ctx.spec_name;
		}
	}
	return ss.view() == value;
}

MATCHER_P(HasNestedException, value, "") {
	try
	{
		std::rethrow_if_nested(arg);
	}
	catch (const std::exception& e)
	{
		return std::string_view(e.what()) == value;
	}
	return false;
}

template<typename ByteType>
struct Asn1TestFixture : public testing::Test
{
	using byte_type = ByteType;
};

using byte_types = testing::Types<std::int8_t, std::uint8_t, std::byte>;

TYPED_TEST_SUITE(Asn1TestFixture, byte_types);

TYPED_TEST(Asn1TestFixture, DecodeInteger1)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2> wrapper;
	EXPECT_THROW(asn1::detail::decode_integer<std::int8_t>(2, wrapper.state),
		std::runtime_error);

	EXPECT_EQ(asn1::detail::decode_integer<std::int8_t>(1, wrapper.state), 1u);
	EXPECT_EQ(asn1::detail::decode_integer<std::int8_t>(1, wrapper.state), 2u);
	EXPECT_THROW(asn1::detail::decode_integer<std::int8_t>(1, wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeInteger2)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3, 4, 5> wrapper;
	EXPECT_EQ(asn1::detail::decode_integer<
		std::int32_t>(3, wrapper.state), 0x010203u);
	EXPECT_EQ(asn1::detail::decode_integer<
		std::int64_t>(2, wrapper.state), 0x0405u);
}

TYPED_TEST(Asn1TestFixture, DecodeInteger3)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3> wrapper;
	EXPECT_THROW(asn1::detail::decode_integer<std::int8_t>(0, wrapper.state),
		std::runtime_error);
	EXPECT_THROW(asn1::detail::decode_integer<std::int64_t>(8, wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeNegativeInteger1)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0xffu> wrapper;
	EXPECT_EQ(asn1::detail::decode_integer<
		std::int8_t>(1, wrapper.state), -1);
}

TYPED_TEST(Asn1TestFixture, DecodeNegativeInteger2)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0xffu> wrapper;
	EXPECT_EQ(asn1::detail::decode_integer<
		std::int32_t>(1, wrapper.state), -1);
}

TYPED_TEST(Asn1TestFixture, DecodeNegativeInteger3)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0xffu, 0xffu, 0xffu> wrapper;
	EXPECT_EQ(asn1::detail::decode_integer<
		std::int32_t>(3, wrapper.state), -1);
}

TYPED_TEST(Asn1TestFixture, DecodeNegativeInteger4)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0xfbu, 0xa7u, 0xc8u> wrapper;
	EXPECT_EQ(asn1::detail::decode_integer<
		std::int64_t>(3, wrapper.state), -284728);
}

TYPED_TEST(Asn1TestFixture, DecodeTypeLength1)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3> wrapper;
	EXPECT_EQ(asn1::detail::der::decode_type_length(wrapper.state),
		(std::pair<std::uint8_t, asn1::detail::length_type>(1, 2)));
	EXPECT_THROW(asn1::detail::der::decode_type_length(wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeTypeLength2)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 0xffu, 3> wrapper;
	EXPECT_THROW(asn1::detail::der::decode_type_length(wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeTypeLength3)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 0x83u, 1, 2, 3> wrapper;
	EXPECT_EQ(asn1::detail::der::decode_type_length(wrapper.state),
		(std::pair<std::uint8_t, asn1::detail::length_type>(1, 0x010203u)));
}

TYPED_TEST(Asn1TestFixture, DecodeTypeLength4)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 0x89u, 1, 2, 3, 4,
		5, 6, 7, 8, 9> wrapper;
	EXPECT_THROW(asn1::detail::der::decode_type_length(wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeBase128_16_Short)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3> wrapper;
	asn1::detail::length_type length = 3u;
	EXPECT_EQ(asn1::detail::decode_base128<std::uint16_t>(length, wrapper.state), 1u);
	EXPECT_EQ(length, 2u);
}

TYPED_TEST(Asn1TestFixture, DecodeBase128_16_Long)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x86u, 0xf7u, 0x0du, 0x00u> wrapper;
	asn1::detail::length_type length = 4u;
	EXPECT_EQ(asn1::detail::decode_base128<std::uint32_t>(length, wrapper.state), 113549u);
	EXPECT_EQ(length, 1u);
}

TYPED_TEST(Asn1TestFixture, DecodeBase128_16_LongTooSmallInt)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x86u, 0xf7u, 0x0du, 0x00u> wrapper;
	asn1::detail::length_type length = 4u;
	EXPECT_THROW(asn1::detail::decode_base128<std::uint16_t>(length, wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeBase128_16_LongErrorTooShortLength)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x86u, 0xf7u, 0x0du, 0x00u> wrapper;
	asn1::detail::length_type length = 2u;
	EXPECT_THROW(asn1::detail::decode_base128<std::uint32_t>(length, wrapper.state),
		std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeOid)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x2au, 0x86u, 0x48u, 0x86u, 0xf7u, 0x0du, 0x01u, 0x01u, 0x0bu> wrapper;
	EXPECT_EQ((asn1::detail::decode_oid<std::vector<std::uint32_t>, false>(
		wrapper.vec.size(), wrapper.state)),
		(std::vector<std::uint32_t>{1, 2, 840, 113549, 1, 1, 11}));
	EXPECT_EQ(wrapper.state.begin, wrapper.state.end);
}

TYPED_TEST(Asn1TestFixture, DecodeOid2)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x88u, 0x37u> wrapper;
	EXPECT_EQ((asn1::detail::decode_oid<std::vector<std::uint32_t>, false>(
		wrapper.vec.size(), wrapper.state)),
		(std::vector<std::uint32_t>{2, 999}));
	EXPECT_EQ(wrapper.state.begin, wrapper.state.end);
}

TYPED_TEST(Asn1TestFixture, DecodeRelOid)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x88u, 0x37u> wrapper;
	EXPECT_EQ((asn1::detail::decode_oid<std::vector<std::uint32_t>, true>(
		wrapper.vec.size(), wrapper.state)),
		(std::vector<std::uint32_t>{1079}));
	EXPECT_EQ(wrapper.state.begin, wrapper.state.end);
}

static_assert(asn1::encode_oid<1, 2, 840, 113549, 1, 1, 11>()
	== std::array<std::uint8_t, 9u>{0x2au,
		0x86u, 0x48u, 0x86u, 0xf7u, 0x0du, 0x01u, 0x01u, 0x0bu});
static_assert(asn1::encode_oid<2, 999, 3>()
	== std::array<std::uint8_t, 3u>{0x88u, 0x37u, 0x03u});

TYPED_TEST(Asn1TestFixture, DecodeOidTooShort)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x2au, 0x86u, 0x48u, 0x86u, 0xf7u> wrapper;
	EXPECT_THROW((asn1::detail::decode_oid<std::vector<std::uint32_t>, false>(
		wrapper.vec.size(), wrapper.state)), std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, DecodeOidTooShort2)
{
	buffer_wrapper_base<typename TestFixture::byte_type> wrapper;
	EXPECT_THROW((asn1::detail::decode_oid<std::vector<std::uint32_t>, false>(
		wrapper.vec.size(), wrapper.state)), std::runtime_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitInteger)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 2, 3, 1, 2, 3, 4> wrapper;
	std::int32_t value{};
	ASSERT_NO_THROW(asn1::der::decode<asn1::spec::integer<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value));
	EXPECT_EQ(value, 0x010203u);
}

TYPED_TEST(Asn1TestFixture, ImplicitInteger)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 2, 3, 1, 2, 3, 4> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::integer<>, std::int64_t>;
	int64_t value{};
	ASSERT_NO_THROW(decoder::decode_implicit(5, value, wrapper.state));
	EXPECT_EQ(value, 0x0203010203ull);
}

TYPED_TEST(Asn1TestFixture, ExplicitEnumerated)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 10, 3, 1, 2, 3, 4> wrapper;
	int32_t value{};
	ASSERT_NO_THROW(asn1::der::decode<asn1::spec::enumerated<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value));
	EXPECT_EQ(value, 0x010203u);
}

namespace
{
enum class test_enum : std::int64_t
{
	test_value = 0x010203
};
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitEnumeratedWithEnum)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 10, 3, 1, 2, 3, 4> wrapper;
	test_enum value{};
	ASSERT_NO_THROW(asn1::der::decode<asn1::spec::enumerated<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value));
	EXPECT_EQ(value, test_enum::test_value);
}

TYPED_TEST(Asn1TestFixture, ExplicitBoolean)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 1, 0xffu> wrapper;
	EXPECT_TRUE((asn1::der::decode<bool, asn1::spec::boolean<>>(
		wrapper.vec.begin(), wrapper.vec.end())));
}

TYPED_TEST(Asn1TestFixture, ImplicitBoolean)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::boolean<>, bool>;
	bool value = true;
	ASSERT_NO_THROW(decoder::decode_implicit(1, value, wrapper.state));
	EXPECT_FALSE(value);
}

TYPED_TEST(Asn1TestFixture, ImplicitBooleanTooLong)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::boolean<asn1::opts::options<asn1::opts::name<"MyBool">>>,
		bool>;
	bool value = true;
	EXPECT_THAT(([&]() { decoder::decode_implicit(2, value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("MyBool")));
}

TYPED_TEST(Asn1TestFixture, ExplicitNull)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 5, 0> wrapper;
	EXPECT_EQ(((asn1::der::decode<std::nullptr_t, asn1::spec::null<>>(
		wrapper.vec.begin(), wrapper.vec.end()))), nullptr);
}

TYPED_TEST(Asn1TestFixture, ImplicitNull)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::null<>, std::nullptr_t>;
	std::nullptr_t value;
	ASSERT_NO_THROW(decoder::decode_implicit(0, value, wrapper.state));
}

TYPED_TEST(Asn1TestFixture, ImplicitNullTooLong)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::null<asn1::opts::options<asn1::opts::name<"MyNull">>>,
		std::nullptr_t>;
	std::nullptr_t value;
	EXPECT_THAT(([&]() { decoder::decode_implicit(1, value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("MyNull")));
}

TYPED_TEST(Asn1TestFixture, ExplicitAnyVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3, 4, 5> wrapper;
	std::vector<typename TestFixture::byte_type> value;
	ASSERT_NO_THROW(asn1::der::decode<asn1::spec::any<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value));
	EXPECT_EQ(value,
		(buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3, 4>{}.vec));
}

TYPED_TEST(Asn1TestFixture, ExplicitAnySpan)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3, 4, 5> wrapper;
	std::span<const typename TestFixture::byte_type> value;
	ASSERT_NO_THROW(asn1::der::decode<asn1::spec::any<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value));
	ASSERT_EQ(value.size(), 4);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin()));
}

TYPED_TEST(Asn1TestFixture, ImplicitAnyVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3, 4, 5> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::any<>, std::vector<typename TestFixture::byte_type>>;
	ASSERT_TRUE(decoder::can_decode(0));
	ASSERT_TRUE(decoder::can_decode(1));
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(3, value, wrapper.state));
	EXPECT_EQ(value, (buffer_wrapper_base<typename TestFixture::byte_type, 1, 2, 3>{}.vec));
}

TYPED_TEST(Asn1TestFixture, AnyErrorContext)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 10, 3, 4, 5> wrapper;
	std::span<const typename TestFixture::byte_type> value;
	EXPECT_THAT([&]() { asn1::der::decode<
		asn1::spec::any<asn1::opts::options<asn1::opts::name<"MyAny">>>>(
			wrapper.vec.begin(), wrapper.vec.end(), value); },
		Throws<asn1::parse_error>(HasContext("MyAny")));
}

namespace
{
template<typename Spec, asn1::tag_type Tag = 3>
using explicit_spec = asn1::spec::tagged<Tag, asn1::spec::encoding::expl,
	asn1::spec::cls::context_specific, Spec>;
template<typename Spec, asn1::tag_type Tag = 5>
using implicit_spec = asn1::spec::tagged<Tag, asn1::spec::encoding::impl,
	asn1::spec::cls::context_specific, Spec>;
} //namespace

TYPED_TEST(Asn1TestFixture, TaggedImplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x85u, 0x01u, 0x05u> wrapper;
	//[5] IMPLICIT INTEGER
	using spec = implicit_spec<asn1::spec::integer<>>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedExplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa3u, 0x03u, 0x02u, 0x01u, 0x05> wrapper;
	//[3] EXPLICIT INTEGER
	using spec = explicit_spec<asn1::spec::integer<>>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedImplicitExplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa5u, 0x03u, 0x02u, 0x01u, 0x05u> wrapper;
	//[5] IMPLICIT [3] EXPLICIT INTEGER
	using spec = implicit_spec<explicit_spec<asn1::spec::integer<>>>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedExplicitImplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa3u, 0x03u, 0x85u, 0x01u, 0x05u> wrapper;
	//[3] EXPLICIT [5] IMPLICIT INTEGER
	using spec = explicit_spec<implicit_spec<asn1::spec::integer<>>>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, Tagged3Implicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x85, 0x01, 0x05> wrapper;
	//[5] IMPLICIT [6] IMPLICIT [7] IMPLICIT INTEGER
	using spec = implicit_spec<implicit_spec<implicit_spec<asn1::spec::integer<>, 7>, 6>, 5>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedIIEII)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa4u, 0x03u, 0x87u, 0x01u, 0x05u> wrapper;
	//[4] IMPLICIT [5] IMPLICIT [6] EXPLICIT [7] IMPLICIT [8] IMPLICIT INTEGER
	using spec = implicit_spec<
		implicit_spec<
			explicit_spec<
				implicit_spec<
					implicit_spec<asn1::spec::integer<>, 8>,
					7
				>,
				6
			>,
			5
		>,
		4
	>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedIIEIE)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa4u, 0x05u, 0xa7u, 0x03u, 0x02u, 0x01u, 0x05u> wrapper;
	//[4] IMPLICIT [5] IMPLICIT [6] EXPLICIT [7] IMPLICIT [8] EXPLICIT INTEGER
	using spec = implicit_spec<
		implicit_spec<
			explicit_spec<
				implicit_spec<
					explicit_spec<asn1::spec::integer<>, 8>,
					7
				>,
				6
			>,
			5
		>,
		4
	>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedEII)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa6u, 0x03u, 0x87u, 0x01u, 0x05u> wrapper;
	//[6] EXPLICIT [7] IMPLICIT [8] IMPLICIT INTEGER
	using spec = explicit_spec<
		implicit_spec<
			implicit_spec<asn1::spec::integer<>, 8>,
			7
		>,
		6
	>;
	EXPECT_EQ((asn1::der::decode<std::int8_t, spec>(
		wrapper.vec.begin(), wrapper.vec.end())), 0x05u);
}

TYPED_TEST(Asn1TestFixture, TaggedAny)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0xa3u, 0x03u, 0x02u, 0x01u, 0x05> wrapper;
	std::span<const typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<explicit_spec<asn1::spec::any<>>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.size(), 3u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

namespace
{
using tagged_choice = asn1::spec::tagged<4u, asn1::spec::encoding::expl, asn1::spec::cls::context_specific,
	asn1::spec::choice<
		asn1::spec::sequence_of<asn1::spec::integer<>>
	>>;
} //namespace
//

TYPED_TEST(Asn1TestFixture, TaggedChoice)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0xa4, 5, 0x30, 3, 2, 1, 5> wrapper;
	std::variant<std::vector<std::int16_t>> value;
	ASSERT_NO_THROW((asn1::der::decode<tagged_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));

	const auto& vec = std::get<std::vector<std::int16_t>>(value);
	ASSERT_EQ(vec.size(), 1u);
	EXPECT_EQ(vec[0], 5);
}

namespace
{
using int_bool_choice = asn1::spec::choice<asn1::spec::boolean<>, asn1::spec::integer<>>;
} //namespace

TYPED_TEST(Asn1TestFixture, ChoiceFirst)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 1, 0xffu> wrapper;
	std::variant<bool, std::int16_t> value;
	ASSERT_NO_THROW((asn1::der::decode<int_bool_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE(std::holds_alternative<bool>(value));
	EXPECT_TRUE(std::get<bool>(value));
}

TYPED_TEST(Asn1TestFixture, ChoiceSecond)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 2, 1, 5> wrapper;
	std::variant<bool, std::int16_t> value;
	ASSERT_NO_THROW((asn1::der::decode<int_bool_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE(std::holds_alternative<std::int16_t>(value));
	EXPECT_EQ(std::get<std::int16_t>(value), 5u);
}

namespace
{
using null_choice = asn1::spec::choice<
	implicit_spec<asn1::spec::null<>, 1>,
	implicit_spec<asn1::spec::null<>, 2>>;
using nested_choice = asn1::spec::choice<
	asn1::spec::null<>,
	null_choice,
	int_bool_choice
>;
using nested_choice_type = std::variant<
	std::nullptr_t,
	std::variant<std::nullptr_t, std::nullptr_t>,
	std::variant<bool, std::int32_t>
>;
} //namespace

TYPED_TEST(Asn1TestFixture, NestedChoiceInt)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 2, 1, 123u> wrapper;
	nested_choice_type value;
	ASSERT_NO_THROW((asn1::der::decode<nested_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE((std::holds_alternative<std::variant<bool, std::int32_t>>(value)));
	const auto& nested = std::get<std::variant<bool, std::int32_t>>(value);
	ASSERT_TRUE((std::holds_alternative<std::int32_t>(nested)));
	EXPECT_EQ(std::get<std::int32_t>(nested), 123u);
}

TYPED_TEST(Asn1TestFixture, NestedChoiceNull)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 5, 0> wrapper;
	nested_choice_type value;
	ASSERT_NO_THROW((asn1::der::decode<nested_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE((std::holds_alternative<std::nullptr_t>(value)));
}

TYPED_TEST(Asn1TestFixture, NestedChoiceNestedNull)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x82u, 0> wrapper;
	nested_choice_type value;
	ASSERT_NO_THROW((asn1::der::decode<nested_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE((std::holds_alternative<std::variant<std::nullptr_t, std::nullptr_t>>(value)));
	const auto& nested = std::get<std::variant<std::nullptr_t, std::nullptr_t>>(value);
	EXPECT_EQ(nested.index(), 1u);
}

TYPED_TEST(Asn1TestFixture, NestedChoiceError)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x83u, 0> wrapper;
	nested_choice_type value;
	EXPECT_THROW(asn1::der::decode<nested_choice>(
		wrapper.vec.begin(), wrapper.vec.end(), value), asn1::parse_error);
}

namespace
{
struct nested_sequence_type
{
	std::int8_t v1;
	std::int16_t v2;
	bool v3;
};

using nested_sequence_spec = asn1::spec::sequence_with_options<
	asn1::opts::named<"nested_sequence_spec">,
	explicit_spec<asn1::spec::integer<asn1::opts::named<"int5">>, 5>,
	asn1::spec::optional_default<asn1::spec::default_value<12345u>,
		asn1::spec::integer<asn1::opts::named<"int_default">>>,
	asn1::spec::boolean<asn1::opts::named<"boolean">>
>;

struct sequence_type
{
	bool v1;
	std::optional<std::nullptr_t> v2;
	std::optional<nested_sequence_type> nested;
};

using sequence_spec = asn1::spec::sequence_with_options<
	asn1::opts::named<"sequence_spec">,
	asn1::spec::boolean<asn1::opts::named<"boolean">>,
	asn1::spec::optional<asn1::spec::null<asn1::opts::named<"null">>>,
	asn1::spec::optional<nested_sequence_spec>
>;
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceAllFields)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0bu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0x78u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 0x78u);
	EXPECT_TRUE(value.nested->v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequencePartFields1)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x0fu,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x08u,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 12345u); //default value assigned
	EXPECT_TRUE(value.nested->v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequencePartFields2)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x0du,
			0x01u, 0x01u, 0xffu,
			0x30u, 0x08u,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_FALSE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 12345u); //default value assigned
	EXPECT_TRUE(value.nested->v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequencePartFields3)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x03u,
			0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_FALSE(value.v2);
	EXPECT_FALSE(value.nested);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceMissingRequired)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x0fu,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x08u,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0xabu
	> wrapper;
	sequence_type value{};
	EXPECT_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)), asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceNotAllDataConsumed)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x14u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0du,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0xabu,
				0x01u, 0x01u, 0xffu,
				0x05u, 0x00u
	> wrapper;
	sequence_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("sequence_spec/nested_sequence_spec")));
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceWrongType)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0bu,
				0xa6u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0xabu,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("sequence_spec/nested_sequence_spec")));
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceWrongType2)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0bu,
				0xa5u, 0x03u, 0x01u, 0x01u, 0x55u,
				0x02u, 0x01u, 0xabu,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("sequence_spec/nested_sequence_spec/int5")));
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceAllFieldsWithIterators)
{
	struct sequence_type_with_iterators
	{
		asn1::with_iterators<std::vector<typename TestFixture::byte_type>::iterator, bool> v1;
		std::optional<std::nullptr_t> v2;
		std::optional<asn1::with_iterators<
			std::vector<typename TestFixture::byte_type>::iterator, nested_sequence_type>> nested;
	};

	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0bu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0x78u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type_with_iterators value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));

	EXPECT_TRUE(value.v1.value);
	EXPECT_EQ(value.v1.begin, wrapper.vec.begin() + 2);
	EXPECT_EQ(value.v1.end, wrapper.vec.begin() + 2 + 3);

	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->begin, wrapper.vec.begin() + 7);
	EXPECT_EQ(value.nested->end, wrapper.vec.end());

	EXPECT_EQ(value.nested->value.v1, 0x55u);
	EXPECT_EQ(value.nested->value.v2, 0x78u);
	EXPECT_TRUE(value.nested->value.v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceAllFieldsWithPointers)
{
	struct sequence_type_with_pointers
	{
		asn1::with_pointers<typename TestFixture::byte_type, bool> v1;
		std::optional<std::nullptr_t> v2;
		std::optional<asn1::with_pointers<
			typename TestFixture::byte_type, nested_sequence_type>> nested;
	};

	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0bu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0x78u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type_with_pointers value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));

	EXPECT_TRUE(value.v1.value);
	EXPECT_EQ(value.v1.begin, wrapper.vec.data() + 2);
	EXPECT_EQ(value.v1.end, wrapper.vec.data() + 2 + 3);

	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->begin, wrapper.vec.data() + 7);
	EXPECT_EQ(value.nested->end, wrapper.vec.data() + wrapper.vec.size());

	EXPECT_EQ(value.nested->value.v1, 0x55u);
	EXPECT_EQ(value.nested->value.v2, 0x78u);
	EXPECT_TRUE(value.nested->value.v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSequenceAllFieldsWithRawData)
{
	struct sequence_type_with_raw_data
	{
		asn1::with_raw_data<std::vector<TestFixture::byte_type>, bool> v1;
		std::optional<std::nullptr_t> v2;
		std::optional<asn1::with_raw_data<
			std::vector<TestFixture::byte_type>, nested_sequence_type>> nested;
	};

	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x30u, 0x0bu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0x78u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	sequence_type_with_raw_data value{};
	ASSERT_NO_THROW((asn1::der::decode<sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));

	EXPECT_TRUE(value.v1.value);
	EXPECT_TRUE(std::equal(value.v1.raw.begin(), value.v1.raw.end(),
		wrapper.vec.begin() + 2));

	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_TRUE(std::equal(value.nested->raw.begin(),
		value.nested->raw.end(), wrapper.vec.begin() + 7));

	EXPECT_EQ(value.nested->value.v1, 0x55u);
	EXPECT_EQ(value.nested->value.v2, 0x78u);
	EXPECT_TRUE(value.nested->value.v3);
}

namespace
{
template<typename ByteType>
struct any_sequence_type
{
	std::int32_t v1;
	std::optional<std::vector<ByteType>> any;
};

using any_sequence_spec = asn1::spec::sequence<
	asn1::spec::integer<>,
	asn1::spec::optional<asn1::spec::any<>>
>;
} //namespace

TYPED_TEST(Asn1TestFixture, AnyOptionalSequenceExplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x08u,
			0x02u, 0x01u, 0x57u,
			0x83u, 0x03u, 0xaau, 0xbbu, 0xccu
	> wrapper;
	
	any_sequence_type<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<any_sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.v1, 0x57u);
	ASSERT_TRUE(value.any);
	EXPECT_EQ(*value.any, (buffer_wrapper_base<typename TestFixture::byte_type,
		0x83u, 0x03u, 0xaau, 0xbbu, 0xccu>{}.vec));
}

TYPED_TEST(Asn1TestFixture, AnyOptionalSequenceExplicitNoAny)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x03u,
			0x02u, 0x01u, 0x57u
	> wrapper;

	any_sequence_type<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<any_sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.v1, 0x57u);
	EXPECT_FALSE(value.any);
}

TYPED_TEST(Asn1TestFixture, AnyOptionalSequenceImplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x02u, 0x01u, 0x57u,
		0x83u, 0x03u, 0xaau, 0xbbu, 0xccu
	> wrapper;
	
	any_sequence_type<typename TestFixture::byte_type> value{};
	using any_sequence_spec_decoder = asn1::detail::der::der_decoder<
		asn1::decode_state<typename std::vector<typename TestFixture::byte_type>::const_iterator>,
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		any_sequence_spec, any_sequence_type<typename TestFixture::byte_type>>;
	ASSERT_NO_THROW(any_sequence_spec_decoder::decode_implicit(wrapper.vec.size(),
		value, wrapper.state));
	EXPECT_EQ(value.v1, 0x57u);
	ASSERT_TRUE(value.any);
	EXPECT_EQ(*value.any, (buffer_wrapper_base<typename TestFixture::byte_type,
		0x83u, 0x03u, 0xaau, 0xbbu, 0xccu>{}.vec));
}

namespace
{
struct extended_sequence_type
{
	std::int32_t v1;
	std::optional<bool> v2;
	asn1::extension_sentinel extension;
};

using extended_sequence_spec = asn1::spec::sequence<
	asn1::spec::integer<>,
	asn1::spec::optional<asn1::spec::boolean<>>,
	asn1::spec::extension_marker<>
>;
} //namespace

TYPED_TEST(Asn1TestFixture, ExtendedSequenceExplicitAllFields)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x06u,
			0x02u, 0x01u, 0x57u,
			0x01u, 0x01u, 0xff
	> wrapper;

	extended_sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<extended_sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.v1, 0x57u);
	EXPECT_EQ(value.v2, true);
}

TYPED_TEST(Asn1TestFixture, ExtendedSequenceExplicitSomeFields)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x03u,
			0x02u, 0x01u, 0x57u
	> wrapper;

	extended_sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<extended_sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.v1, 0x57u);
	EXPECT_FALSE(value.v2);
}

TYPED_TEST(Asn1TestFixture, ExtendedSequenceExplicitExtension)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x0fu,
			0x02u, 0x01u, 0x57u,
			0x01u, 0x01u, 0xff,
			0x83, 0x05, 1, 2, 3, 4, 5,
			0xa5, 0x00
	> wrapper;

	extended_sequence_type value{};
	ASSERT_NO_THROW((asn1::der::decode<extended_sequence_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.v1, 0x57u);
	EXPECT_EQ(value.v2, true);
}

TYPED_TEST(Asn1TestFixture, SequenceOfExplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x07u,
			0x02u, 0x02u, 0x03u, 0x05u,
			0x02u, 0x01u, 0x07u
	> wrapper;

	using spec = asn1::spec::sequence_of<asn1::spec::integer<>>;
	std::vector<std::int16_t> value{};
	ASSERT_NO_THROW((asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (std::vector<std::int16_t>{ 0x0305u, 0x07u }));
}

TYPED_TEST(Asn1TestFixture, SequenceOfImplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x02u, 0x02u, 0x03u, 0x05u,
		0x02u, 0x01u, 0x07u
	> wrapper;

	using spec = asn1::spec::sequence_of<asn1::spec::integer<>>;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		spec, std::vector<std::int16_t>>;
	std::vector<std::int16_t> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	EXPECT_EQ(value, (std::vector<std::int16_t>{ 0x0305u, 0x07u }));
}

TYPED_TEST(Asn1TestFixture, SequenceOfExplicitEmpty)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 0x30u, 0x00u> wrapper;

	using spec = asn1::spec::sequence_of<asn1::spec::integer<>>;
	std::vector<std::int16_t> value{};
	ASSERT_NO_THROW((asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.empty());
}

TYPED_TEST(Asn1TestFixture, SequenceOfChoiceExplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x07u,
			0x02u, 0x02u, 0x03u, 0x05u,
			0x01u, 0x01u, 0xffu
	> wrapper;

	using spec = asn1::spec::sequence_of<int_bool_choice>;
	using value_type = std::vector<std::variant<bool, std::int16_t>>;
	value_type value{};
	ASSERT_NO_THROW((asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 2u);
	ASSERT_TRUE(std::holds_alternative<std::int16_t>(value[0]));
	ASSERT_TRUE(std::holds_alternative<bool>(value[1]));
	EXPECT_EQ(std::get<std::int16_t>(value[0]), 0x0305u);
	EXPECT_TRUE(std::get<bool>(value[1]));
}

TYPED_TEST(Asn1TestFixture, SequenceOfExplicitError)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x07u,
			0x02u, 0x02u, 0x03u, 0x05u,
			0x01u, 0x01u, 0x07u
	> wrapper;

	using spec = asn1::spec::sequence_of<
		asn1::spec::integer<asn1::opts::options<asn1::opts::name<"MyInt">>>
	>;
	std::vector<std::int16_t> value{};
	EXPECT_THAT(([&]() { asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasContext("MyInt")));
	EXPECT_EQ(value, (std::vector<std::int16_t>{ 0x0305u, 0u }));
}

TYPED_TEST(Asn1TestFixture, SetOfExplicit)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x07u,
			0x02u, 0x02u, 0x03u, 0x05u,
			0x02u, 0x01u, 0x07u
	> wrapper;

	using spec = asn1::spec::set_of<asn1::spec::integer<>>;
	std::vector<std::int16_t> value{};
	ASSERT_NO_THROW((asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (std::vector<std::int16_t>{ 0x0305u, 0x07u }));
}

namespace
{
struct nested_set_type
{
	std::int8_t v1;
	std::int16_t v2;
	bool v3;
};

using nested_set_spec = asn1::spec::set<
	explicit_spec<asn1::spec::integer<>, 5>,
	asn1::spec::optional_default<asn1::spec::default_value<12345u>, asn1::spec::integer<>>,
	asn1::spec::boolean<>
>;

struct set_type
{
	bool v1;
	std::optional<std::nullptr_t> v2;
	std::optional<nested_set_type> nested;
};

using set_spec = asn1::spec::set<
	asn1::spec::boolean<asn1::opts::options<asn1::opts::name<"MyBoolean">>>,
	asn1::spec::optional<asn1::spec::null<>>,
	asn1::spec::optional<nested_set_spec>
>;
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitNestedSetAllFieldsInOrder)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x12u,
			0x01u, 0x01u, 0xffu,
			0x05u, 0x00u,
			0x31u, 0x0bu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x02u, 0x01u, 0x78u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	set_type value{};
	ASSERT_NO_THROW((asn1::der::decode<set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 0x78u);
	EXPECT_TRUE(value.nested->v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSetAllFieldsOutOfOrder)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x12u,
			0x05u, 0x00u,
			0x31u, 0x0bu,
				0x02u, 0x01u, 0x78u,
				0x01u, 0x01u, 0xffu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
			0x01u, 0x01u, 0xffu
	> wrapper;
	set_type value{};
	ASSERT_NO_THROW((asn1::der::decode<set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 0x78u);
	EXPECT_TRUE(value.nested->v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSetDuplicateFields)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x15u,
			0x05u, 0x00u,
			0x01u, 0x01u, 0xffu,
			0x31u, 0x0bu,
				0x02u, 0x01u, 0xabu,
				0x01u, 0x01u, 0xffu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
			0x01u, 0x01u, 0xffu
	> wrapper;
	set_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasContext("MyBoolean")));
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSetMissingOptionalFields)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x0du,
			0x01u, 0x01u, 0xffu,
			0x31u, 0x08u,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
				0x01u, 0x01u, 0xffu
	> wrapper;
	set_type value{};
	ASSERT_NO_THROW((asn1::der::decode<set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);
	EXPECT_FALSE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 12345u); //default value assigned
	EXPECT_TRUE(value.nested->v3);
}

TYPED_TEST(Asn1TestFixture, ExplicitNestedSetMissingRequiredFields)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x0fu,
			0x05u, 0x00u,
			0x31u, 0x0bu,
				0x02u, 0x01u, 0xabu,
				0x01u, 0x01u, 0xffu,
				0xa5u, 0x03u, 0x02u, 0x01u, 0x55u
	> wrapper;
	set_type value{};
	EXPECT_THROW(asn1::der::decode<set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value), asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ImplicitNestedSetAllFieldsOutOfOrder)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x05u, 0x00u,
		0x31u, 0x0bu,
			0x02u, 0x01u, 0x78u,
			0x01u, 0x01u, 0xffu,
			0xa5u, 0x03u, 0x02u, 0x01u, 0x55u,
		0x01u, 0x01u, 0xffu
	> wrapper;
	set_type value{};

	using set_spec_decoder = asn1::detail::der::der_decoder<
		asn1::decode_state<typename std::vector<typename TestFixture::byte_type>::const_iterator>,
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		set_spec, set_type>;
	ASSERT_NO_THROW(set_spec_decoder::decode_implicit(
		wrapper.vec.size(), value, wrapper.state));
	EXPECT_TRUE(value.v1);
	EXPECT_TRUE(value.v2);
	ASSERT_TRUE(value.nested);
	EXPECT_EQ(value.nested->v1, 0x55u);
	EXPECT_EQ(value.nested->v2, 0x78u);
	EXPECT_TRUE(value.nested->v3);
};

namespace
{
using choice2 = asn1::spec::choice_with_options<
	asn1::opts::options<asn1::opts::name<"Choice2">>,
	explicit_spec<asn1::spec::integer<>, 8u>,
	explicit_spec<asn1::spec::boolean<>, 9u>
>;
using choice3 = asn1::spec::choice<
	explicit_spec<asn1::spec::integer<>, 6u>,
	explicit_spec<asn1::spec::boolean<>, 7u>
>;

struct choice_set_type
{
	bool v1;
	std::optional<nested_choice_type> c1;
	std::variant<int16_t, bool> c2;
	std::variant<int32_t, bool> c3;
};

using choice_set_spec = asn1::spec::set_with_options<
	asn1::opts::named<"choice_set_spec">,
	explicit_spec<asn1::spec::boolean<>, 3u>,
	asn1::spec::optional<nested_choice>,
	asn1::spec::optional_default<asn1::spec::default_value<true>, choice2>,
	choice3
>;
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitSetNestedOptionalChoiceAllPresent)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x12u,
			0xa8u, 0x03u, 0x02u, 0x01u, 0x55u, //std::variant<int16_t, bool> c2
			0x02u, 0x01u, 0x78u, //std::optional<nested_choice_type> c1
			0xa3u, 0x03u, 0x01u, 0x01u, 0xffu, //bool v1
			0xa7u, 0x03u, 0x01u, 0x01u, 0xffu //std::variant<int32_t, bool> c3
	> wrapper;
	choice_set_type value{};
	ASSERT_NO_THROW((asn1::der::decode<choice_set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);

	ASSERT_TRUE(value.c1);
	ASSERT_TRUE((std::holds_alternative<std::variant<bool, std::int32_t>>(*value.c1)));
	auto c1_nested = std::get<std::variant<bool, std::int32_t>>(*value.c1);
	ASSERT_TRUE(std::holds_alternative<std::int32_t>(c1_nested));
	EXPECT_EQ(std::get<std::int32_t>(c1_nested), 0x78u);

	ASSERT_TRUE(std::holds_alternative<std::int16_t>(value.c2));
	EXPECT_EQ(std::get<std::int16_t>(value.c2), 0x55u);

	ASSERT_TRUE(std::holds_alternative<bool>(value.c3));
	EXPECT_TRUE(std::get<bool>(value.c3));
}

TYPED_TEST(Asn1TestFixture, ExplicitSetNestedOptionalChoiceSomePresent)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x0au,
			0xa7u, 0x03u, 0x01u, 0x01u, 0xffu, //std::variant<int32_t, bool> c3
			0xa3u, 0x03u, 0x01u, 0x01u, 0xffu //bool v1
	> wrapper;
	choice_set_type value{};
	ASSERT_NO_THROW((asn1::der::decode<choice_set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_TRUE(value.v1);

	EXPECT_FALSE(value.c1);

	ASSERT_TRUE(std::holds_alternative<bool>(value.c2));
	EXPECT_TRUE(std::get<bool>(value.c2)); //default value assigned

	ASSERT_TRUE(std::holds_alternative<bool>(value.c3));
	EXPECT_TRUE(std::get<bool>(value.c3));
}

namespace
{
template<typename ByteType>
using optional_choice_duplicate_wrapper = buffer_wrapper_base<ByteType,
	0x31u, 0x17u,
		0xa8u, 0x03u, 0x02u, 0x01u, 0x55u, //std::variant<int16_t, bool> c2
		0x02u, 0x01u, 0xabu, //std::optional<nested_choice_type> c1
		0xa3u, 0x03u, 0x01u, 0x01u, 0xffu, //bool v1
		0xa7u, 0x03u, 0x01u, 0x01u, 0xffu, //std::variant<int32_t, bool> c3
		0xa9u, 0x03u, 0x02u, 0x01u, 0x55u //duplicate std::variant<int16_t, bool> c2
>;
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitSetNestedOptionalChoiceDuplicateFullErrorContext)
{
	optional_choice_duplicate_wrapper<typename TestFixture::byte_type> wrapper;
	choice_set_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<choice_set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("choice_set_spec/Choice2")));
}

TYPED_TEST(Asn1TestFixture, ExplicitSetNestedOptionalChoiceDuplicateLastErrorContext)
{
	optional_choice_duplicate_wrapper<typename TestFixture::byte_type> wrapper;
	choice_set_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<choice_set_spec,
		asn1::decode_options<asn1::decode_opts::error_context_policy::last_context>>(
			wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("Choice2")));
}

TYPED_TEST(Asn1TestFixture, ExplicitSetNestedOptionalChoiceDuplicateNoErrorContext)
{
	optional_choice_duplicate_wrapper<typename TestFixture::byte_type> wrapper;
	choice_set_type value{};
	EXPECT_THAT(([&]() { asn1::der::decode<choice_set_spec,
		asn1::decode_options<asn1::decode_opts::error_context_policy::no_context>>(
			wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("")));
}

TYPED_TEST(Asn1TestFixture, ExplicitSetNestedOptionalChoiceNoRequired)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x0du,
			0xa8u, 0x03u, 0x02u, 0x01u, 0x55u, //std::variant<int16_t, bool> c2
			0x02u, 0x01u, 0xabu, //std::optional<nested_choice_type> c1
			0xa3u, 0x03u, 0x01u, 0x01u, 0xffu //bool v1
	> wrapper;
	choice_set_type value{};
	EXPECT_THROW(asn1::der::decode<choice_set_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value), asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitOctetStringVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 4, 2, 3, 4, 5> wrapper;
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::octet_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (buffer_wrapper_base<typename TestFixture::byte_type, 3, 4>{}.vec));
}

TYPED_TEST(Asn1TestFixture, ExplicitOctetStringSpan)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 4, 2, 3, 4, 5> wrapper;
	std::span<const typename TestFixture::byte_type> value;
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::octet_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 2u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

TYPED_TEST(Asn1TestFixture, ExplicitOctetStringWith)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 4, 3, 2, 1, 3> wrapper;
	int value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::octet_string_with<asn1::spec::integer<>>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, 3);
}

TYPED_TEST(Asn1TestFixture, ExplicitOctetStringWithException)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 4, 3, 3, 1, 3> wrapper;
	int value{};
	EXPECT_THAT(([&]() { asn1::der::decode<asn1::spec::octet_string_with<
		asn1::spec::integer<asn1::opts::named<"int">>, asn1::opts::named<"str">>
		>(wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("str/int")));
}

TYPED_TEST(Asn1TestFixture, ImplicitOctetStringVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 4, 2, 3, 4, 5> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::octet_string<>, std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(2, value, wrapper.state));
	EXPECT_EQ(value, (buffer_wrapper_base<typename TestFixture::byte_type, 4, 2>{}.vec));
}

TYPED_TEST(Asn1TestFixture, ExplicitBitStringVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 3, 3, 1, 25, 26> wrapper;
	asn1::bit_string<std::vector<typename TestFixture::byte_type>> value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::bit_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.bit_count, 15u);
	EXPECT_EQ(value.container, (buffer_wrapper_base<typename TestFixture::byte_type, 25, 26>{}.vec));
}

TYPED_TEST(Asn1TestFixture, ExplicitBitStringSpan)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 3, 3, 1, 25, 26> wrapper;
	asn1::bit_string<std::span<const typename TestFixture::byte_type>> value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::bit_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.bit_count, 15u);
	ASSERT_EQ(value.container.size(), 2u);
	EXPECT_TRUE(std::equal(value.container.begin(),
		value.container.end(), wrapper.vec.begin() + 3u));
}

TYPED_TEST(Asn1TestFixture, ImplicitBitStringVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 1, 25, 26> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::bit_string<>, asn1::bit_string<std::vector<typename TestFixture::byte_type>>>;
	asn1::bit_string<std::vector<typename TestFixture::byte_type>> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(3, value, wrapper.state));
	EXPECT_EQ(value.bit_count, 15u);
	EXPECT_EQ(value.container, (buffer_wrapper_base<
		typename TestFixture::byte_type, 25, 26>{}.vec));
}

TYPED_TEST(Asn1TestFixture, ExplicitBitStringSpanTooManyUnusedBits)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 3, 1, 1> wrapper;
	asn1::bit_string<std::span<const typename TestFixture::byte_type>> value{};
	EXPECT_THAT(([&]() { asn1::der::decode<asn1::spec::bit_string<asn1::opts::named<"bits">>>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasContext("bits")));
}

namespace
{
struct custom_bit_string_parse_options
{
	static constexpr bool ignore_bit_string_invalid_unused_count = true;
};
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitBitStringSpanTooManyUnusedBitsIgnore)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 3, 1, 1> wrapper;
	asn1::bit_string<std::span<const typename TestFixture::byte_type>> value{};

	using custom_decode_options = asn1::decode_options<
		asn1::decode_opts::error_context_policy::full_context, custom_bit_string_parse_options>;

	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::bit_string<>, custom_decode_options>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.bit_count, 0u);
	ASSERT_EQ(value.container.size(), 0u);
}

TYPED_TEST(Asn1TestFixture, ExplicitOidNoDecode)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x06u, 0x09u, 0x2au, 0x86u, 0x48u, 0x86u,
		0xf7u, 0x0du, 0x01u, 0x01u, 0x0bu> wrapper;
	std::vector<typename TestFixture::byte_type> value;
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::object_identifier<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 9u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

TYPED_TEST(Asn1TestFixture, ExplicitOidDecode)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x06u, 0x09u, 0x2au, 0x86u, 0x48u, 0x86u,
		0xf7u, 0x0du, 0x01u, 0x01u, 0x0bu> wrapper;
	asn1::decoded_object_identifier<std::vector<std::uint32_t>> value;
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::object_identifier<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.container, (std::vector<std::uint32_t>{1, 2, 840, 113549, 1, 1, 11}));
}

TYPED_TEST(Asn1TestFixture, ExplicitRelOidDecode)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x0du, 0x09u, 0x2au, 0x86u, 0x48u, 0x86u,
		0xf7u, 0x0du, 0x01u, 0x01u, 0x0bu> wrapper;
	asn1::decoded_object_identifier<std::vector<std::uint32_t>> value;
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::relative_oid<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value.container, (std::vector<std::uint32_t>{42, 840, 113549, 1, 1, 11}));
}

TYPED_TEST(Asn1TestFixture, ExplicitOidDecodeTooSmallType)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x06u, 0x09u, 0x2au, 0x86u, 0x48u, 0x86u,
		0xf7u, 0x0du, 0x01u, 0x01u, 0x0bu> wrapper;
	asn1::decoded_object_identifier<std::vector<std::uint16_t>> value;
	EXPECT_THAT(([&]() { asn1::der::decode<
		asn1::spec::object_identifier<asn1::opts::options<asn1::opts::name<"MyOID">>>>(
			wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasContext("MyOID")));
}

template<typename Types>
struct Asn1StringTestFixture : public testing::Test
{
	using string_spec_type = typename Types::first_type;
	using byte_type = typename Types::second_type;
};

using string_spec_types = testing::Types<
	std::pair<asn1::spec::numeric_string<>, std::int8_t>,
	std::pair<asn1::spec::printable_string<>, std::int8_t>,
	std::pair<asn1::spec::ia5_string<>, std::int8_t>,
	std::pair<asn1::spec::teletex_string<>, std::int8_t>,
	std::pair<asn1::spec::videotex_string<>, std::int8_t>,
	std::pair<asn1::spec::visible_string<>, std::int8_t>,
	std::pair<asn1::spec::graphic_string<>, std::int8_t>,
	std::pair<asn1::spec::general_string<>, std::int8_t>,
	std::pair<asn1::spec::object_descriptor<>, std::int8_t>,
	std::pair<asn1::spec::utf8_string<>, std::int8_t>,

	std::pair<asn1::spec::numeric_string<>, std::uint8_t>,
	std::pair<asn1::spec::printable_string<>, std::uint8_t>,
	std::pair<asn1::spec::ia5_string<>, std::uint8_t>,
	std::pair<asn1::spec::teletex_string<>, std::uint8_t>,
	std::pair<asn1::spec::videotex_string<>, std::uint8_t>,
	std::pair<asn1::spec::visible_string<>, std::uint8_t>,
	std::pair<asn1::spec::graphic_string<>, std::uint8_t>,
	std::pair<asn1::spec::general_string<>, std::uint8_t>,
	std::pair<asn1::spec::object_descriptor<>, std::uint8_t>,
	std::pair<asn1::spec::utf8_string<>, std::uint8_t>,

	std::pair<asn1::spec::numeric_string<>, std::byte>,
	std::pair<asn1::spec::printable_string<>, std::byte>,
	std::pair<asn1::spec::ia5_string<>, std::byte>,
	std::pair<asn1::spec::teletex_string<>, std::byte>,
	std::pair<asn1::spec::videotex_string<>, std::byte>,
	std::pair<asn1::spec::visible_string<>, std::byte>,
	std::pair<asn1::spec::graphic_string<>, std::byte>,
	std::pair<asn1::spec::general_string<>, std::byte>,
	std::pair<asn1::spec::object_descriptor<>, std::byte>,
	std::pair<asn1::spec::utf8_string<>, std::byte>
>;

TYPED_TEST_SUITE(Asn1StringTestFixture, string_spec_types);

TYPED_TEST(Asn1StringTestFixture, ExplicitStrSpan)
{
	using string_spec_type = typename TestFixture::string_spec_type;

	buffer_wrapper_base<typename TestFixture::byte_type,
		string_spec_type::tag(), 3, 'a', 'b', 'c'> wrapper;
	std::span<const typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<string_spec_type>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 3u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

TYPED_TEST(Asn1StringTestFixture, ImplicitStrVector)
{
	using string_spec_type = typename TestFixture::string_spec_type;

	buffer_wrapper_base<typename TestFixture::byte_type,
		'a', 'b', 'c'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>, string_spec_type,
		std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	ASSERT_EQ(value.size(), 3u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin()));
}

TYPED_TEST(Asn1StringTestFixture, ExplicitStrString)
{
	using string_spec_type = typename TestFixture::string_spec_type;

	buffer_wrapper_base<typename TestFixture::byte_type,
		string_spec_type::tag(), 3, 'a', 'b', 'c'> wrapper;
	std::string value{};
	ASSERT_NO_THROW((asn1::der::decode<string_spec_type>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, "abc");
}

TYPED_TEST(Asn1TestFixture, ExplicitUtf8StrSpan)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		12, 3, 'a', 'b', 'c'> wrapper;
	std::span<const typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::utf8_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 3u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

TYPED_TEST(Asn1TestFixture, ImplicitUtf8StrVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'a', 'b', 'c'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::utf8_string<>,
		std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	ASSERT_EQ(value.size(), 3u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin()));
}

TYPED_TEST(Asn1TestFixture, ExplicitUtf8StrString)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		12, 3, 'a', 'b', 'c'> wrapper;
	std::u8string value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::utf8_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, u8"abc");
}

TYPED_TEST(Asn1TestFixture, ExplicitBmpStrSpan)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		30, 6, 'a', 'b', 'c', 'd', 'e', 'f'> wrapper;
	std::span<const typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::bmp_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 6u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

TYPED_TEST(Asn1TestFixture, ImplicitBmpStringVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'a', 'b', 'c', 'd', 'e', 'f'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::bmp_string<>,
		std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	ASSERT_EQ(value.size(), 6u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin()));
}

TYPED_TEST(Asn1TestFixture, ImplicitBmpStringLengthError)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'a', 'b', 'c', 'd', 'e'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::bmp_string<>,
		std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	EXPECT_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state),
		asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitBmpStrString)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		30, 6, '\0', 'b', '\0', 'd', '\0', 'f'> wrapper;
	std::u16string value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::bmp_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, u"bdf");
}

TYPED_TEST(Asn1TestFixture, ImplicitBmpStrStringLengthError)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'\0', 'b', '\0', 'd', '\0'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::bmp_string<>,
		std::u16string>;
	std::u16string value{};
	EXPECT_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state),
		asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitUniversalStrSpan)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		28, 8, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'> wrapper;
	std::span<const typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::universal_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_EQ(value.size(), 8u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin() + 2u));
}

TYPED_TEST(Asn1TestFixture, ImplicitUniversalStringVector)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::universal_string<>,
		std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	ASSERT_NO_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	ASSERT_EQ(value.size(), 8u);
	EXPECT_TRUE(std::equal(value.begin(), value.end(), wrapper.vec.begin()));
}

TYPED_TEST(Asn1TestFixture, ImplicitUniversalStringLengthError)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'a', 'b', 'c', 'd', 'e', 'f'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::universal_string<>,
		std::vector<typename TestFixture::byte_type>>;
	std::vector<typename TestFixture::byte_type> value{};
	EXPECT_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state),
		asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitUniversalStrString)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		28, 8, '\0', '\0', '\0', 'd', '\0', '\0', '\0', 'f'> wrapper;
	std::u32string value{};
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::universal_string<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, U"df");
}

TYPED_TEST(Asn1TestFixture, ImplicitUniversalStrStringLengthError)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'\0', '\0', '\0', 'd', '\0', '\0'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::universal_string<>,
		std::u32string>;
	std::u32string value{};
	EXPECT_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state),
		asn1::parse_error);
}

TYPED_TEST(Asn1TestFixture, ExplicitUtcTime)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		23, 13, '1', '2', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', 'Z'> wrapper;
	asn1::utc_time value;
	ASSERT_NO_THROW((asn1::der::decode<asn1::spec::utc_time<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (asn1::utc_time{12, 5, 24, 11, 22, 33}));
}

TYPED_TEST(Asn1TestFixture, ImplicitUtcTime)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '0', '5', '2', '4', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	using decoder = asn1::detail::der::der_decoder<decltype(wrapper.state),
		asn1::decode_options<>, asn1::detail::parent_context_list<>,
		asn1::spec::utc_time<>, asn1::utc_time>;
	asn1::utc_time value;
	ASSERT_NO_THROW(decoder::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	EXPECT_EQ(value, (asn1::utc_time{ 12, 5, 24, 11, 22, 33 }));
}

namespace
{
template<typename ByteType>
using named_utc_time_decoder = asn1::detail::der::der_decoder<
	asn1::decode_state<typename std::vector<ByteType>::const_iterator>,
	asn1::decode_options<>, asn1::detail::parent_context_list<>,
	asn1::spec::utc_time<asn1::opts::options<asn1::opts::name<"UtcTime">>>,
	asn1::utc_time>;

template<typename ByteType>
using named_utc_time_leap_year_decoder = asn1::detail::der::der_decoder<
	asn1::decode_state<typename std::vector<ByteType>::const_iterator>,
	asn1::decode_options<>, asn1::detail::parent_context_list<>,
	asn1::spec::utc_time<asn1::opts::options<asn1::opts::name<"UtcTime">,
		asn1::opts::zero_year<2000u>>>,
	asn1::utc_time>;

template<typename BufferWrapper>
void test_utc_time_error(BufferWrapper& wrapper)
{
	asn1::utc_time value;
	EXPECT_THAT(([&]() { named_utc_time_decoder<typename BufferWrapper::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("UtcTime")));
}
} //namespace

TYPED_TEST(Asn1TestFixture, UtcTimeValidateZ)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '0', '5', '2', '4', '1',
		'1', '2', '2', '3', '3', 'X'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidateMonth)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '1', '4', '2', '4', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidateHour)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '0', '5', '2', '4', '2',
		'4', '2', '2', '3', '3', 'Z'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidateMinute)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '0', '5', '2', '4', '1',
		'1', '6', '0', '3', '3', 'Z'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidateSecond)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '0', '5', '2', '4', '1',
		'1', '2', '2', '6', '0', 'Z'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidateDay)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', '2', '0', '5', '3', '2', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidateIntegers)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'1', 'f', '0', '5', '3', '2', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	test_utc_time_error(wrapper);
}

TYPED_TEST(Asn1TestFixture, UtcTimeNoValidate29February)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'0', '5', '0', '2', '2', '9', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	asn1::utc_time value;
	ASSERT_NO_THROW(named_utc_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(),
		value, wrapper.state));
	EXPECT_EQ(value, (asn1::utc_time{ 5, 2, 29, 11, 22, 33 }));
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidate29FebruaryError)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'0', '5', '0', '2', '2', '9', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	asn1::utc_time value;
	EXPECT_THAT(([&]() { named_utc_time_leap_year_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("UtcTime")));
}

TYPED_TEST(Asn1TestFixture, UtcTimeValidate29February)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'9', '6', '0', '2', '2', '9', '1',
		'1', '2', '2', '3', '3', 'Z'> wrapper;
	asn1::utc_time value;
	ASSERT_NO_THROW(named_utc_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(),
		value, wrapper.state));
	EXPECT_EQ(value, (asn1::utc_time{ 96, 2, 29, 11, 22, 33 }));
}

namespace
{
using generalized_time_spec = asn1::spec::generalized_time<
	asn1::opts::options<asn1::opts::name<"GeneralizedTime">>>;
template<typename ByteType>
using generalized_time_decoder = asn1::detail::der::der_decoder<
	asn1::decode_state<typename std::vector<ByteType>::const_iterator>,
	asn1::decode_options<>, asn1::detail::parent_context_list<>,
	generalized_time_spec,
	asn1::generalized_time>;
} //namespace

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeNoFraction)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 15, '2', '5', '9', '1', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', 'Z'> wrapper;
	asn1::generalized_time value;
	ASSERT_NO_THROW((asn1::der::decode<generalized_time_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	asn1::generalized_time expected{ 2591, 5, 24, 11, 22, 33 };
	EXPECT_EQ(value, expected);
}

TYPED_TEST(Asn1TestFixture, ImplicitGeneralizedTimeNoFraction)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		'2', '5', '9', '1', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', 'Z'> wrapper;
	asn1::generalized_time value;
	ASSERT_NO_THROW(generalized_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state));
	asn1::generalized_time expected{ 2591, 5, 24, 11, 22, 33 };
	EXPECT_EQ(value, expected);
}

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeFraction)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 21, '2', '5', '9', '1', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', '.', '1', '2', '3', '4', '5', 'Z'> wrapper;
	asn1::generalized_time value;
	ASSERT_NO_THROW((asn1::der::decode<generalized_time_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (asn1::generalized_time{ 2591, 5, 24, 11, 22, 33, 12345 }));
}

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeFractionNoSuffix)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 20, '2', '5', '9', '1', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', '.', '1', '2', '3', '4', '5'> wrapper;
	asn1::generalized_time value;
	EXPECT_THAT(([&]() { generalized_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("GeneralizedTime")));
}

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeFractionTrailingZeros)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 18, '2', '5', '9', '1', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', '.', '1', '0', 'Z'> wrapper;
	asn1::generalized_time value;
	EXPECT_THAT(([&]() { generalized_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("GeneralizedTime")));
}

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeFractionWrongPoint)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 18, '2', '5', '9', '1', '0', '5', '2', '4', '1', '1',
		'2', '2', '3', '3', ',', '1', '0', 'Z'> wrapper;
	asn1::generalized_time value;
	EXPECT_THAT(([&]() { generalized_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("GeneralizedTime")));
}

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeFractionFeb29Error)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 17, '2', '5', '9', '1', '0', '2', '2', '9', '1', '1',
		'2', '2', '3', '3', '.', '1', 'Z'> wrapper;
	asn1::generalized_time value;
	EXPECT_THAT(([&]() { generalized_time_decoder<typename TestFixture::byte_type>
		::decode_implicit(wrapper.vec.size(), value, wrapper.state); }),
		Throws<asn1::parse_error>(HasContext("GeneralizedTime")));
}

TYPED_TEST(Asn1TestFixture, ExplicitGeneralizedTimeFractionFeb29)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		24, 17, '1', '9', '9', '6', '0', '2', '2', '9', '1', '1',
		'2', '2', '3', '3', '.', '1', 'Z'> wrapper;
	asn1::generalized_time value;
	ASSERT_NO_THROW((asn1::der::decode<generalized_time_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (asn1::generalized_time{ 1996, 2, 29, 11, 22, 33, 1 }));
}

namespace
{
struct linked_list_spec : asn1::spec::recursive<linked_list_spec>
{
	using type = asn1::spec::sequence<
		asn1::spec::integer<>,
		asn1::spec::choice<
			asn1::spec::null<>,
			linked_list_spec
		>
	>;
};

using recursive_spec = asn1::spec::sequence<
	asn1::spec::boolean<>,
	linked_list_spec
>;

struct variant_linked_list
{
	std::int32_t value;
	std::variant<std::nullptr_t, std::unique_ptr<variant_linked_list>> next;
};

struct variant_linked_list_wrapper
{
	bool value;
	variant_linked_list list;
};
} //namespace

TYPED_TEST(Asn1TestFixture, RecursiveVariantLinkedList)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x19u,
			0x01u, 0x01u, 0xffu,
			0x30u, 0x14u,
				0x02u, 0x01u, 0x01u,
				0x30u, 0x0fu,
					0x02u, 0x01u, 0x02u,
					0x30u, 0x0au,
						0x02u, 0x01u, 0x03u,
						0x30u, 0x05u,
							0x02u, 0x01u, 0x04u,
							0x05u, 0x00u
	> wrapper;
	variant_linked_list_wrapper value;
	ASSERT_NO_THROW((asn1::der::decode<recursive_spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE(value.value);

	const auto& list1 = value.list;
	ASSERT_EQ(list1.value, 1u);
	ASSERT_EQ(list1.next.index(), 1u);

	const auto& list2 = std::get<1>(list1.next);
	ASSERT_NE(list2, nullptr);
	ASSERT_EQ(list2->value, 2u);
	ASSERT_EQ(list2->next.index(), 1u);

	const auto& list3 = std::get<1>(list2->next);
	ASSERT_NE(list3, nullptr);
	ASSERT_EQ(list3->value, 3u);
	ASSERT_EQ(list3->next.index(), 1u);

	const auto& list4 = std::get<1>(list3->next);
	ASSERT_NE(list4, nullptr);
	ASSERT_EQ(list4->value, 4u);
	ASSERT_EQ(list4->next.index(), 0u);
}

namespace
{
struct optional_linked_list_spec : asn1::spec::recursive<optional_linked_list_spec>
{
	using type = asn1::spec::sequence_with_options<
		asn1::opts::named<"LinkedListNode">,
		asn1::spec::integer<>,
		asn1::spec::optional<optional_linked_list_spec>
	>;
};

using optional_recursive_spec = asn1::spec::sequence_with_options<
	asn1::opts::named<"LinkedList">,
	asn1::spec::boolean<>,
	optional_linked_list_spec
>;

struct optional_linked_list
{
	std::int32_t value;
	std::unique_ptr<optional_linked_list> next;
};

struct optional_linked_list_wrapper
{
	bool value;
	optional_linked_list list;
};

template<typename ByteType>
using optional_list_wrapper_type = buffer_wrapper_base<ByteType,
	0x30u, 0x17u,
		0x01u, 0x01u, 0xffu,
		0x30u, 0x12u,
			0x02u, 0x01u, 0x01u,
			0x30u, 0x0du,
				0x02u, 0x01u, 0x02u,
				0x30u, 0x08u,
					0x02u, 0x01u, 0x03u,
					0x30u, 0x03u,
						0x02u, 0x01u, 0x04u
>;
} //namespace

TYPED_TEST(Asn1TestFixture, RecursiveOptionalLinkedListWithRecursionDepth)
{
	optional_list_wrapper_type<typename TestFixture::byte_type> wrapper;
	optional_linked_list_wrapper value;
	ASSERT_NO_THROW((asn1::der::decode<optional_recursive_spec>(100u,
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	ASSERT_TRUE(value.value);

	const auto& list1 = value.list;
	ASSERT_EQ(list1.value, 1u);
	ASSERT_TRUE(list1.next);

	const auto list2 = list1.next.get();
	ASSERT_NE(list2, nullptr);
	ASSERT_EQ(list2->value, 2u);
	ASSERT_TRUE(list2->next);

	const auto list3 = list2->next.get();
	ASSERT_NE(list3, nullptr);
	ASSERT_EQ(list3->value, 3u);
	ASSERT_TRUE(list3->next);

	const auto list4 = list3->next.get();
	ASSERT_NE(list4, nullptr);
	ASSERT_EQ(list4->value, 4u);
	ASSERT_FALSE(list4->next);
}

TYPED_TEST(Asn1TestFixture, RecursiveOptionalLinkedListWithRecursionDepthError)
{
	optional_list_wrapper_type<typename TestFixture::byte_type> wrapper;
	optional_linked_list_wrapper value;
	EXPECT_THAT(([&]() { asn1::der::decode<optional_recursive_spec>(3u,
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(HasExactContext("LinkedList/LinkedListNode")));
}

TYPED_TEST(Asn1TestFixture, Validators)
{
    constexpr auto validator = [](int val){ if (val > 5) throw std::runtime_error("Too big"); };
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x31u, 0x09u, 2, 1, 5, 2, 1, 10, 2, 1, 1> wrapper;
	using spec = asn1::spec::set_of_with_options<
		asn1::opts::named<"set_of">,
		asn1::spec::integer<asn1::opts::options<
			asn1::opts::name<"int">,
			asn1::opts::validator_func<validator>
		>>
	>;
	std::vector<int> value;
	EXPECT_THAT(([&]() { asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value); }),
		Throws<asn1::parse_error>(AllOf(HasExactContext("set_of/int"), HasNestedException("Too big"))));
	ASSERT_EQ(value.size(), 2u);
	EXPECT_EQ(value[0], 5u);
}

TYPED_TEST(Asn1TestFixture, TaggedExplicitFwdIterator)
{
	using type = typename TestFixture::byte_type;
	std::forward_list<type> vec{
		static_cast<type>(0xa3u),
		static_cast<type>(0x03u),
		static_cast<type>(0x02u),
		static_cast<type>(0x01u),
		static_cast<type>(0x05u) };
	//[3] EXPLICIT INTEGER
	int8_t value{};
	ASSERT_NO_THROW((asn1::der::decode<explicit_spec<asn1::spec::integer<>>>(
		vec.begin(), vec.end(), value)));
	EXPECT_EQ(value, 0x05u);
}

TYPED_TEST(Asn1TestFixture, SequenceOfLimits)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x07u,
		0x02u, 0x02u, 0x03u, 0x05u,
		0x02u, 0x01u, 0x07u
	> wrapper;

	using spec = asn1::spec::sequence_of_with_options<
		asn1::opts::options<asn1::opts::min_max_elements<1, 2>>,
		asn1::spec::integer<>>;
	std::vector<std::int16_t> value{};
	ASSERT_NO_THROW((asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)));
	EXPECT_EQ(value, (std::vector<std::int16_t>{ 0x0305u, 0x07u }));
}

TYPED_TEST(Asn1TestFixture, SequenceOfTooManyElems)
{
	buffer_wrapper_base<typename TestFixture::byte_type,
		0x30u, 0x07u,
		0x02u, 0x02u, 0x03u, 0x05u,
		0x02u, 0x01u, 0x07u
	> wrapper;

	using spec = asn1::spec::sequence_of_with_options<
		asn1::opts::options<asn1::opts::min_max_elements<1, 1>>,
		asn1::spec::integer<>>;
	std::vector<std::int16_t> value{};
	EXPECT_THROW((asn1::der::decode<spec>(
		wrapper.vec.begin(), wrapper.vec.end(), value)), asn1::parse_error);
}

namespace
{
namespace my_spec
{
using my_choice = asn1::spec::choice<
	asn1::spec::tagged<
		1, asn1::spec::encoding::impl, asn1::spec::cls::context_specific,
		asn1::spec::integer<>
	>,
	asn1::spec::tagged<
		2, asn1::spec::encoding::expl, asn1::spec::cls::context_specific,
		asn1::spec::ia5_string<>
	>,
	asn1::spec::octet_string<>
>;

using some_data_structure = asn1::spec::sequence<
	asn1::spec::optional_default<asn1::spec::default_value<123>, asn1::spec::integer<>>,
	asn1::spec::optional<asn1::spec::boolean<>>,
	my_choice,
	asn1::spec::set_of<asn1::spec::integer<>>
>;
} // namespace my_spec

using my_choice = std::variant<
	std::int32_t,
	std::string,
	std::span<const std::uint8_t>>;

struct some_data_structure
{
	std::int64_t integral_value;
	std::optional<bool> boolean_value;
	my_choice choice_value;
	std::vector<std::int16_t> list_of_values;
};

TEST(Asn1Test, ComplexDataParse)
{
	std::vector<std::uint8_t> data{
		0x30, 0x13, // SEQUENCE
			0x01, 0x01, 0xff, // BOOLEAN
			0xa2, 0x05, 0x16, 0x03, 'a', 'b', 'c', // CHOICE with IA5String
			0x31, 0x07, //SET OF
				0x02, 0x02, 0x10, 0x20, //INTEGER
				0x02, 0x01, 0x25 //INTEGER
	};

	auto result = asn1::der::decode<some_data_structure, // Data structure to use for parsing
		my_spec::some_data_structure // Our specification
	>(data.begin(), data.end());

	EXPECT_EQ(result.integral_value, 123);
	EXPECT_EQ(result.boolean_value, true);
	auto choice_value = std::get_if<std::string>(&result.choice_value);
	ASSERT_NE(choice_value, nullptr);
	EXPECT_EQ(*choice_value, "abc");
	EXPECT_EQ(result.list_of_values, (std::vector<std::int16_t>{ 0x1020, 0x25 }));
}
} // namespace

#include "boost/multiprecision/cpp_int.hpp"

namespace asn1::detail::der
{
template<typename DecodeState,
	typename Options, typename ParentContexts, typename SpecOptions>
struct der_decoder<DecodeState, Options, ParentContexts, spec::integer<SpecOptions>,
	boost::multiprecision::cpp_int>
	: der_decoder_base<der_decoder<DecodeState, Options,
		ParentContexts, spec::integer<SpecOptions>, boost::multiprecision::cpp_int>>
{
	static constexpr const char* length_decode_error_text = "Expected INTEGER";

	static void decode_implicit_impl(length_type len, boost::multiprecision::cpp_int& value,
		DecodeState& state)
	{
		value = 0;
		if (!len)
			return;

		bool is_signed = static_cast<std::uint8_t>(*state.begin) & 0x80u;
		while (len--)
		{
			value <<= std::numeric_limits<std::uint8_t>::digits;
			auto byte = static_cast<std::uint8_t>(*state.begin++);
			value |= static_cast<std::uint8_t>(is_signed ? ~byte : byte);
		}
		if (is_signed)
			value = -value - 1;
	}
};
} //namespace asn1::detail::der

TYPED_TEST(Asn1TestFixture, ExplicitIntegerCustom)
{
	buffer_wrapper_base<typename TestFixture::byte_type, 2, 2, 0x80, 0x22> wrapper;
	boost::multiprecision::cpp_int value;
	ASSERT_NO_THROW(asn1::der::decode<asn1::spec::integer<>>(
		wrapper.vec.begin(), wrapper.vec.end(), value));
	//EXPECT_EQ(value, 32802);
	EXPECT_EQ(value, -32734);
}

int main(int argc, char** argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
