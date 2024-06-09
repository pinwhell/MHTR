#pragma once

#include <cstdint>
#include <string>

constexpr auto METADATA_OFFSET_INVALID = -1;
constexpr auto METADATA_STRING_INVALID = "";
constexpr auto METADATA_NULL_NS = "";

template<typename T>
struct Metadata {
	Metadata(T val)
		: mValue(val)
	{}

	Metadata<T> operator+(const Metadata<T>& other) const = delete;
	void operator+=(const Metadata<T>& other) = delete;

	std::string ToString() const;

	Metadata<T>& operator=(const T&& val)
	{
		mValue = val;
		return *this;
	}

	operator T() const
	{
		return mValue;
	}

	T mValue;
};

using OffsetMetadata = Metadata<uint64_t>;
using PatternMetadata = Metadata<std::string>;
