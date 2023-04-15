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
	onNotSucessComputing();
	auto name = mpFutureResultInfo->getUidentifier();
	printf("\"%s\" with %d Results\n", name.c_str(), mScanAlgo->getResults().size());
}

uintptr_t FutureOffset::getSingleResult()
{
	if (mScanAlgo->getResults().size() != 1)
		return 0;

	return *(mScanAlgo->getResults().begin());
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

	mNeedCapstone = mScanAlgo->getNeedCapstone();

	//printf("\t%s Need Capstone: %s\n", getName().c_str(), mNeedCapstone ? "Yes" : "No");

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
