#include "IOffsetScanAlgo.h"
#include "FutureOffset.h"

bool IOffsetScanAlgo::Init()
{
	mMainDisp = mAlgoMetadata.get<int64_t>("disp", 0);

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

const std::vector<uintptr_t>& IOffsetScanAlgo::getResults()
{
	return mResults;
}

void IOffsetScanAlgo::setAlgoMetadata(const JsonValueWrapper& metadata)
{
	mAlgoMetadata = metadata;
}

void IOffsetScanAlgo::HandleAllDisp()
{
	ContainerDisplacer::Displace<std::vector<uintptr_t>, int64_t>(mResults.begin(), mResults.end(), mMainDisp);
	// Right after the scan finish, applying the Displacement predefined at the metadata or 0 if none defined
}

void IOffsetScanAlgo::setBufferInfo(const char* buff, size_t buffSz)
{
	mBuffer = buff;
	mBuffSize = buffSz;
}
