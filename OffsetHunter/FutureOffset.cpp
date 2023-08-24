#include "FutureOffset.h"
#include "ScanAlgoClassifier.h"
#include "SingleDumpTarget.h"

FutureOffset::FutureOffset()
{
	mpFutureResultInfo = &mFutureResultInfo;
}

void FutureOffset::OnFound()
{
	mFutureResultInfo.setFinalOffset(getSingleResult()); // Guaranteed to be one
	onSucessfullyComputed();
}

void FutureOffset::OnNotFound()
{
	onNotSucessComputing();
	auto name = mpFutureResultInfo->getUidentifier();
	printf("\"%s\" Not found\n", name.c_str());
}

void FutureOffset::OnMultipleFound()
{
	if (getFutureResultInfo()->CanPickAnyResult() == false)
	{
		onNotSucessComputing();
		auto name = mpFutureResultInfo->getUidentifier();
		printf("\"%s\" with %d Results\n", name.c_str(), mScanAlgo->getResults().size());

		return;
	}

	mFutureResultInfo.setFinalOffset(getFirstResult()); // Picking the first
	onSucessfullyComputed();
}

uintptr_t FutureOffset::getSingleResult()
{
	if (mScanAlgo->getResults().size() != 1)
		return 0;

	return getFirstResult();
}

uintptr_t FutureOffset::getFirstResult()
{
	return *(mScanAlgo->getResults().begin());
}

ICapstoneHelper* FutureOffset::getCapstoneHelper()
{
	return mParent->getCapstoneHelper(mScanAlgo->getCapstoneMode());
}

bool FutureOffset::Init()
{
	if (IFutureResult::Init() == false)
		return false;

	if (ScanAlgoClassifier::Classify(mMetadata, mScanAlgo) == false)
		return false;

	mScanAlgo->setParent(this);
	mScanAlgo->setBufferInfo(mBuffer, mBuffSize);

	if (mScanAlgo->Init() == false)
		return false;

	return true;
}

void FutureOffset::OnScanFinished()
{
	auto results = mScanAlgo->getResults();

	if (results.size() == 1)
		OnFound();
	else if (results.size() == 0)
		OnNotFound();
	else if (results.size() > 1)
		OnMultipleFound();
}

void FutureOffset::IgniteScan()
{
	mScanAlgo->IgniteScan();
}

void FutureOffset::Compute()
{
	IFutureResult::Compute();

	IgniteScan();
}

void FutureOffset::ComputeJsonResult()
{
	if (getDumpDynamic())
		getResultJson()->set<uint64_t>(mFutureResultInfo.getUIDHashStr(), mFutureResultInfo.getFinalObfOffset());
}
