#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace asn1
{
using tag_type = std::uint8_t;

struct extension_sentinel final {};

template<typename Container>
struct [[nodiscard]] bit_string
{
	static_assert(sizeof(typename Container::value_type) == sizeof(std::uint8_t),
		"Expected byte container or span");

	template<typename EnumValue>
	[[nodiscard]] constexpr bool is_set(EnumValue value) const noexcept
	{
		if (bit_count > static_cast<std::size_t>(value))
		{
			std::size_t byte_index = value
				/ std::numeric_limits<std::uint8_t>::digits;
			std::size_t bit_index = (std::numeric_limits<std::uint8_t>::digits - 1)
				- value % std::numeric_limits<std::uint8_t>::digits;
			return (static_cast<std::uint8_t>(container[byte_index])
				& (1u << bit_index)) != 0u;
		}

		return false;
	}

	[[nodiscard]]
	friend auto operator<=>(const bit_string&, const bit_string&) noexcept = default;
	[[nodiscard]]
	friend bool operator==(const bit_string&, const bit_string&) noexcept = default;

	Container container;
	std::size_t bit_count{};
};

template<typename Container>
struct [[nodiscard]] decoded_object_identifier
{
	Container container;

	[[nodiscard]]
	friend auto operator<=>(const decoded_object_identifier&,
		const decoded_object_identifier&) noexcept = default;
	[[nodiscard]]
	friend bool operator==(const decoded_object_identifier&,
		const decoded_object_identifier&) noexcept = default;
};

struct [[nodiscard]] utc_time
{
	std::uint8_t year{};
	std::uint8_t month{}; //1-12
	std::uint8_t day{}; //1-...
	std::uint8_t hour{}; //00-23
	std::uint8_t minute{};
	std::uint8_t second{};

	[[nodiscard]]
	friend auto operator<=>(const utc_time&, const utc_time&) noexcept = default;
	[[nodiscard]]
	friend bool operator==(const utc_time&, const utc_time&) noexcept = default;
};

struct [[nodiscard]] generalized_time
{
	std::uint16_t year{};
	std::uint8_t month{}; //1-12
	std::uint8_t day{}; //1-...
	std::uint8_t hour{}; //00-23
	std::uint8_t minute{};
	std::uint8_t second{};
	std::uint64_t seconds_fraction{};

	[[nodiscard]]
	friend auto operator<=>(const generalized_time&,
		const generalized_time&) noexcept = default;
	[[nodiscard]]
	friend bool operator==(const generalized_time&,
		const generalized_time&) noexcept = default;
};

namespace detail
{
template<std::uint32_t Component>
consteval std::size_t count_bytes_for_oid_component() noexcept
{
	std::size_t bytes = 1;
	std::uint32_t component = Component;
	while (component > 127u)
	{
		++bytes;
		component /= 128u;
	}
	return bytes;
}

template<std::uint32_t Component>
consteval void encode_base128(std::uint8_t*& ptr) noexcept
{
	std::uint32_t component = Component;
	auto end = ptr += count_bytes_for_oid_component<Component>();
	std::uint8_t mask = 0u;
	while (component > 127u)
	{
		*--end = static_cast<std::uint8_t>(component & 0x7fu) | mask;
		component /= 128u;
		mask = 0x80u;
	}
	*--end = static_cast<std::uint8_t>(component) | mask;
}
} //namespace detail

template<std::uint32_t First, std::uint32_t Second, std::uint32_t... Other>
[[nodiscard]]
consteval auto encode_oid() noexcept
{
	constexpr std::uint32_t first_int = First * 40u + Second;
	static_assert(First * 40ull + Second == first_int,
		"First/Second component values are too large");
	constexpr auto array_size
		= detail::count_bytes_for_oid_component<first_int>()
		+ (... + detail::count_bytes_for_oid_component<Other>());
	std::array<std::uint8_t, array_size> result{};
	std::uint8_t* ptr = result.data();

	detail::encode_base128<first_int>(ptr);
	(..., detail::encode_base128<Other>(ptr));
	return result;
}

template<typename Container>
[[nodiscard]] std::string oid_to_string(const Container& container)
{
	std::string result;
	const char* sep = "";
	for (auto value : container)
	{
		result += sep;
		sep = ".";
		result += std::to_string(value);
	}
	return result;
}
} //namespace asn1
