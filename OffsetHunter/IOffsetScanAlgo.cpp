#include "IOffsetScanAlgo.h"
#include "FutureOffset.h"

bool IOffsetScanAlgo::Init()
{
	mDisplacer.setDisp(mAlgoMetadata.get<int64_t>("disp", 0));

	return true;
}

void IOffsetScanAlgo::IgniteScan()
{
	mResults.clear();
}

void IOffsetScanAlgo::OnScanFinished()
{
	HandleAllDisp();

	if (mParent)
		mParent->OnScanFinished();
}

const std::vector<uint64_t>& IOffsetScanAlgo::getResults()
{
	return mResults;
}

void IOffsetScanAlgo::setAlgoMetadata(const JsonValueWrapper& metadata)
{
	mAlgoMetadata = metadata;
}

void IOffsetScanAlgo::setParent(FutureOffset* parent)
{
	mParent = parent;
}

void IOffsetScanAlgo::HandleAllDisp()
{
	if (mResults.empty() == false && mDisplacer.getDisp() != 0)
		mDisplacer.Displace(mResults.begin(), mResults.end());
	// Right after the scan finish, applying the Displacement predefined at the metadata or 0 if none defined
}

void IOffsetScanAlgo::setBufferInfo(const char* buff, size_t buffSz)
{
	mBuffer = buff;
	mBuffSize = buffSz;
}
