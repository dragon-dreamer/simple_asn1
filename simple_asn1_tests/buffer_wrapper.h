#pragma once

#include <cstdint>
#include <vector>

#include "simple_asn1/decode.h"

template<typename ByteType, std::uint8_t... Bytes>
struct buffer_wrapper_base
{
	using byte_type = ByteType;

	std::vector<ByteType> vec{ static_cast<ByteType>(Bytes)... };
	asn1::decode_state<
		typename std::vector<ByteType>::const_iterator,
		typename std::vector<ByteType>::const_iterator>
		state{ vec.cbegin(), vec.cend() };
};

template<std::uint8_t... Bytes>
using buffer_wrapper = buffer_wrapper_base<std::uint8_t, Bytes...>;
