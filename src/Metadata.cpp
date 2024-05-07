#include <Metadata.h>
#include <sstream>
#include <TBS.hpp>
#include <fmt/core.h>
#include <PatternScan.h>
#include <iostream>

template<>
std::string Metadata<uint64_t>::ToString() const {
	std::stringstream ss;
	ss << std::hex << "0x" << mValue;
	return ss.str();
}

template<>
std::string Metadata<std::string>::ToString() const {
	return mValue;
}

template<>
Metadata<uint64_t> Metadata<uint64_t>::operator+(const Metadata<uint64_t>& other) const {
	return Metadata<uint64_t>(mValue + other.mValue);
}

template<>
void Metadata<uint64_t>::operator+=(const Metadata<uint64_t>& other) {
	mValue += other.mValue;
}

MetadataResult::MetadataResult(uint64_t offset)
	: mType(EMetadataResult::OFFSET)
	, mOffset(offset)
{}

MetadataResult::MetadataResult(const std::string & pattern)
	: mType(EMetadataResult::PATTERN)
	, mPattern(pattern.c_str())
{}

MetadataResult::~MetadataResult()
{}

MetadataResult& MetadataResult::operator=(const MetadataResult& other)
{
	switch (other.mType)
	{
	case EMetadataResult::OFFSET:
		mOffset = other.mOffset;
		break;

	case EMetadataResult::PATTERN:
		new (&mPattern) std::string(other.mPattern);
		break;
	}

	return *this;
}

std::string MetadataResult::ToString() const {
	switch (mType)
	{
	case EMetadataResult::PATTERN:
		return mPattern.ToString();
	case EMetadataResult::OFFSET:
		return mOffset.ToString();
	}

	return "";
}

MetadataTarget::MetadataTarget(const std::string& name)
	: mName(name)
	, mResult(0)
	, mDone(false)
{}

MetadataLookupException::MetadataLookupException(const std::string& what)
	: std::runtime_error(what)
{}

PatternCheckLookup::PatternCheckLookup(MetadataTarget& target, const BufferView& scanRange, const std::string& pattern, bool bUniqueLookup)
	: mTarget(target)
	, mScanRange(scanRange)
	, mPattern(pattern)
	, mbUniqueLookup(bUniqueLookup)
{}

void PatternCheckLookup::Lookup() { Check(); }

void PatternCheckLookup::Check()
{
	if (mTarget.ResultIsFound())
		return;

	TBS::Pattern::Results res;
	PatternScanOrExceptWithName(mTarget.mName, mScanRange, mPattern, res, mbUniqueLookup);

	mTarget.TrySetResult(MetadataResult(mPattern));
}

PatternSingleResultLookup::PatternSingleResultLookup(MetadataTarget& target, const BufferView& scanRange, const std::string& pattern)
	: mTarget(target)
	, mScanRange(scanRange)
	, mPattern(pattern)
{}

void PatternSingleResultLookup::Lookup()
{
	if (mTarget.ResultIsFound())
		return;

	TBS::Pattern::Results res;
	PatternScanOrExceptWithName(mTarget.mName, mScanRange, mPattern, res, true);

	mTarget.TrySetResult(MetadataResult(res[0]));
}

InsnImmediateLookup::InsnImmediateLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IRelativeDispProvider* relDispProvider, ICapstone* capstone, size_t immIndex)
	: mCapstone(capstone)
	, mTarget(target)
	, mInsnAddrsProvider(insnAddrsProvider)
	, mRelDispProvider(relDispProvider)
	, mImmIndex(immIndex)
{}

void InsnImmediateLookup::Lookup()
{
	if (mTarget.ResultIsFound())
		return;

	std::vector<uint64_t> insnAddresses = mInsnAddrsProvider->GetAllAddresses();
	std::unordered_set<uint64_t> immResults;

	for (const auto& insnResult : insnAddresses)
	{
		try {
			CapstoneDismHandle hInsns = mCapstone->Disassemble((void*)insnResult, 0x20);
			immResults.insert(mCapstone->getUtility()->InsnGetImmByIndex(hInsns.mpFirst, mImmIndex));
		}
		catch (DismFailedException& e)
		{
			std::cout << fmt::format("'{}':'{}' diassembly failed\n", mTarget.mName, fmt::ptr((void*)mRelDispProvider->OffsetFromBase(insnResult)));
		}
		catch (std::exception& e)
		{
			std::cout << fmt::format("'{}':'{}':{}\n", mTarget.mName, fmt::ptr((void*)mRelDispProvider->OffsetFromBase(insnResult)), e.what());
		}
	}

	if (immResults.size() < 1)
		throw std::runtime_error(fmt::format("'{}' no immediates found.", mTarget.mName));

	if (immResults.size() > 1)
		throw std::runtime_error(fmt::format("'{}' multiple instruction immediates", mTarget.mName));

	mTarget.TrySetResult(MetadataResult(*immResults.begin()));
}