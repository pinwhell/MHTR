#pragma once

#include <cstdint>
#include <string>

constexpr auto METADATA_OFFSET_INVALID = -1;
constexpr auto METADATA_STRING_INVALID = "";

template<typename T>
struct Metadata {
	Metadata(T val)
		: mValue(val)
	{}

	Metadata<T> operator+(const Metadata<T>& other) const = delete;
	void operator+=(const Metadata<T>& other) = delete;	

	std::string ToString() const;

	bool IsValid();

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

enum class EMetadataResult {
	OFFSET,
	PATTERN
};

struct MetadataResult {

	MetadataResult(uint64_t offset);
	MetadataResult(const std::string& pattern);
	MetadataResult(const char* s);
	~MetadataResult();

	std::string ToString() const;

	EMetadataResult mType;

	union {
		OffsetMetadata mOffset;
		PatternMetadata mPattern;
	};
};