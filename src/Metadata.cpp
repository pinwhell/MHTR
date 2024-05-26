#include <Metadata.h>
#include <sstream>
#include <TBS.hpp>
#include <fmt/core.h>
#include <PatternScan.h>
#include <iostream>

#include <CStone/CStone.h>

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
	: mMetadata(offset)
{}

MetadataResult::MetadataResult(const std::string & pattern)
	: mMetadata(pattern)
{}

std::string MetadataResult::ToString() const {
	if (std::holds_alternative<OffsetMetadata>(mMetadata))
		return std::get<OffsetMetadata>(mMetadata).ToString();

	if (std::holds_alternative<PatternMetadata>(mMetadata))
		return std::get<PatternMetadata>(mMetadata).ToString();

	return "";
}

EMetadataResult MetadataResult::getType() const
{
	return (EMetadataResult)mMetadata.index();
}

MetadataTarget::MetadataTarget(const std::string& name, INamespace* ns)
	: mFullIdentifier(name, ns)
	, mResult(0)
	, mHasResult(false)
{}

bool MetadataTarget::TrySetResult(const MetadataResult&& result)
{
	bool _false = false;

	if (mHasResult.compare_exchange_strong(_false, true) == false)
		return false;

	mResult = result;

	return true;
}

std::string MetadataTarget::GetName() const
{
	return mFullIdentifier.mIdentifier;
}

std::string MetadataTarget::GetFullName() const
{
	return mFullIdentifier.GetFullIdentifier();
}

MetadataLookupException::MetadataLookupException(const std::string& what)
	: std::runtime_error(what)
{}

PatternCheckLookup::PatternCheckLookup(MetadataTarget& target, IRangeProvider* scanRange, const std::string& pattern, bool bUniqueLookup)
	: mTarget(target)
	, mScanRange(scanRange)
	, mPattern(pattern)
	, mbUniqueLookup(bUniqueLookup)
{}

void PatternCheckLookup::Lookup() { Check(); }

MetadataTarget* PatternCheckLookup::GetTarget() {
	return &mTarget;
}

void PatternCheckLookup::Check()
{
	if (mTarget.mHasResult)
		return;

	TBS::Pattern::Results res;
	PatternScanOrExceptWithName(mTarget.mFullIdentifier.GetFullIdentifier(), mScanRange, mPattern, res, mbUniqueLookup);

	mTarget.TrySetResult(MetadataResult(mPattern));
}

PatternSingleResultLookup::PatternSingleResultLookup(MetadataTarget& target, IRangeProvider* scanRange, const std::string& pattern)
	: mTarget(target)
	, mScanRange(scanRange)
	, mPattern(pattern)
{}

void PatternSingleResultLookup::Lookup()
{
	if (mTarget.mHasResult)
		return;

	BufferView bv = mScanRange->GetRange();

	TBS::Pattern::Results res;
	PatternScanOrExceptWithName(mTarget.mFullIdentifier.GetFullIdentifier(), mScanRange, mPattern, res, true);

	mTarget.TrySetResult(MetadataResult(bv.OffsetFromBase(res[0])));
}

MetadataTarget* PatternSingleResultLookup::GetTarget() {
	return &mTarget;
}

InsnImmediateLookup::InsnImmediateLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, ICapstoneProvider* cstoneProvider, size_t immIndex)
	: mCStoneProvider(cstoneProvider)
	, mTarget(target)
	, mInsnAddrsProvider(insnAddrsProvider)
	, mImmIndex(immIndex)
{}

void InsnImmediateLookup::Lookup()
{
	if (mTarget.mHasResult)
		return;

	ICapstone* cstone = mCStoneProvider->GetInstance();
	std::vector<uint64_t> insnAddresses = mInsnAddrsProvider->GetAllAddresses();
	std::unordered_set<uint64_t> immResults;

	for (const auto& insnResult : insnAddresses)
	{
		try {
			CapstoneDismHandle hInsns = cstone->Disassemble((void*)insnResult, 0x20);
			immResults.insert(cstone->getUtility()->InsnGetImmByIndex(hInsns.mpFirst, mImmIndex));
		}
		catch (DismFailedException& e)
		{
			std::cout << fmt::format("'{}' diassembly failed\n", mTarget.GetFullName());
		}
		catch (std::exception& e)
		{
			std::cout << fmt::format("'{}':{}\n", mTarget.GetFullName(), e.what());
		}
	}

	if (immResults.size() < 1)
		throw MetadataLookupException(fmt::format("'{}' no immediates found.", mTarget.GetFullName()));

	if (immResults.size() > 1)
		throw MetadataLookupException(fmt::format("'{}' multiple instruction immediates", mTarget.GetFullName()));

	mTarget.TrySetResult(MetadataResult(*immResults.begin()));
}

MetadataTarget* InsnImmediateLookup::GetTarget() {
	return &mTarget;
}

std::unordered_map<std::string, std::vector<MetadataTarget*>> TargetsGetNamespacedMap(const std::vector<MetadataTarget*>& targets)
{
	std::unordered_map<std::string, std::vector<MetadataTarget*>> result;

	for (auto* target : targets)
	{
		const INamespace* targetNs = target->mFullIdentifier.mNamespace;
		std::string targetNsStr = targetNs ? targetNs->GetNamespace() : METADATA_NULL_NS;

		if (result.find(targetNsStr) == result.end())
			result[targetNsStr] = std::vector<MetadataTarget*>();

		result[targetNsStr].push_back(target);
	}

	return result;
}

HardcodedLookup::HardcodedLookup(MetadataTarget& target, const MetadataResult& hardcoded)
	: mTarget(target)
{
	mTarget.TrySetResult(std::move(hardcoded));
}

void HardcodedLookup::Lookup()
{
}

MetadataTarget* HardcodedLookup::GetTarget()
{
	return &mTarget;
}