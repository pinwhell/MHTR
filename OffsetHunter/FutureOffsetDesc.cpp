#include "FutureOffset.h"

FutureOffset::FutureOffset()
{

	mStatus = Status::IDDLE;

}

void FutureOffset::OnFound()
{

}

void FutureOffset::OnNotFound()
{

}

void FutureOffset::OnMultipleFound()
{

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
