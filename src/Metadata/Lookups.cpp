#include <iostream>
#include <fmt/core.h>
#include <MHTR/Metadata/Lookups.h>
#include <MHTR/PatternScan.h>
#include <CStone/CStone.h>

using namespace MHTR;

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

PatternSingleResultLookup::PatternSingleResultLookup(MetadataTarget& target, IRangeProvider* scanRange, IOffsetCalculator* offsetCalculator, const std::string& pattern)
	: mTarget(target)
	, mScanRange(scanRange)
	, mOffsetCalculator(offsetCalculator)
	, mPattern(pattern)
{}

void PatternSingleResultLookup::Lookup()
{
	if (mTarget.mHasResult)
		return;

	TBS::Pattern::Results res;
	PatternScanOrExceptWithName(mTarget.mFullIdentifier.GetFullIdentifier(), mScanRange, mPattern, res, true);

	mTarget.TrySetResult(MetadataResult(mOffsetCalculator->ComputeOffset(res[0])));
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
			std::cerr << fmt::format("'{}' diassembly failed\n", mTarget.GetFullName());
		}
		catch (std::exception& e)
		{
			std::cerr << fmt::format("'{}':{}\n", mTarget.GetFullName(), e.what());
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