#include "IOffsetScanAlgo.h"
#include "FutureOffset.h"

void IOffsetScanAlgo::IgniteScan()
{
	mResults.clear();
}

void IOffsetScanAlgo::OnScanFinished()
{
	if (mParent)
		mParent->OnScanFinished();
}

const std::vector<uint64_t>& IOffsetScanAlgo::getResults()
{
	return mResults;
}
