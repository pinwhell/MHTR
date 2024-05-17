#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <mutex>

#include <CStone/ICapstone.h>

#include <Provider/IAddresses.h>

#include <Synther/NamespacedIdentifier.h>

#include <ILookable.h>
#include <BufferView.h>

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

enum class EMetadataResult {
	OFFSET,
	PATTERN
};

struct MetadataResult {

	MetadataResult(uint64_t offset);
	MetadataResult(const std::string& pattern);
	~MetadataResult();

	MetadataResult& operator=(const MetadataResult& other);

	std::string ToString() const;

	EMetadataResult mType;

	union {
		OffsetMetadata mOffset;
		PatternMetadata mPattern;
	};
};

class MetadataLookupException : public std::runtime_error {
public:
	MetadataLookupException(const std::string& what);
};

struct MetadataTarget {
	MetadataTarget(const std::string& name, INamespace* ns = nullptr);

	bool TrySetResult(const MetadataResult&& result)
	{
		bool _false = false;
		
		if (mHasResult.compare_exchange_strong(_false, true) == false)
			return false;

		mResult = result;

		return true;
	}

	std::string GetName() const;
	std::string GetFullName() const;

	NamespacedIdentifier mFullIdentifier;
	std::atomic<bool> mHasResult;
	MetadataResult mResult;
};

class PatternCheckLookup : public ILookable {
public:
	PatternCheckLookup(MetadataTarget& target, const BufferView& scanRange, const std::string& pattern, bool bUniqueLookup = true);

	void Lookup() override;

	MetadataTarget& mTarget;
	BufferView mScanRange;
	std::string mPattern;
	bool mbUniqueLookup;

private:
	void Check();
};

class PatternSingleResultLookup : public ILookable {
public:
	PatternSingleResultLookup(MetadataTarget& target, const BufferView& scanRange, const std::string& pattern);

	void Lookup() override;

	MetadataTarget& mTarget;
	BufferView mScanRange;
	std::string mPattern;
};

class InsnImmediateLookup : public ILookable {
public:
	InsnImmediateLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IRelativeDispProvider* relDispProvider, ICapstone* capstone, size_t immIndex = 0);

	void Lookup() override;

	IAddressesProvider* mInsnAddrsProvider;
	IRelativeDispProvider* mRelDispProvider;
	ICapstone* mCapstone;
	MetadataTarget& mTarget;
	size_t mImmIndex;
};

std::unordered_map<std::string, std::vector<MetadataTarget*>> TargetsGetNamespacedMap(const std::vector<MetadataTarget*>& targets);
