#include "FutureOffset.h"
#include "ScanAlgoClassifier.h"
#include "SingleDumpTarget.h"

FutureOffset::FutureOffset()
{
	
}

void FutureOffset::OnFound()
{
	mOffsetInfo.setFinalOffset(mScanAlgo->getResults()[0]); // Guaranteed to be one
}

void FutureOffset::OnNotFound()
{
	auto name = getName();
	printf("\"%s\" Not found\n", name.c_str());
}

void FutureOffset::OnMultipleFound()
{
	auto name = getName();
	printf("\"%s\" with %d Results\n", name.c_str(), mScanAlgo->getResults().size());
}

bool FutureOffset::Init()
{
	if (IOffset::Init() == false)
		return false;

	if (ScanAlgoClassifier::Classify(mOffsetInfo.getMetadata(), mScanAlgo) == false)
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

void FutureOffset::ComputeOffset()
{
	IgniteScan();
}
