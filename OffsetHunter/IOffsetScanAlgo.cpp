#include "IOffsetScanAlgo.h"
#include "FutureOffset.h"
#include "ICapstoneHelper.h"
#include "TargetManager.h"

bool IOffsetScanAlgo::Init()
{
	mMainDisp = mAlgoMetadata.get<int64_t>("disp", 0);

	mTryInterpret = mAlgoMetadata.get<bool>("interpret", true);

	if (mTryInterpret)
	{
		mCapstoneMode = mAlgoMetadata.get<std::string>("mode", "default");
		mParent->getParent()->ReportCapstoneNeededMode(mCapstoneMode);
		//printf("\t%s Need Capstone: %s\n", getName().c_str(), mNeedCapstone ? "Yes" : "No");
	}

	return true;
}

void IOffsetScanAlgo::IgniteScan()
{
	mResults.clear();
	mFilteredResults.clear();
}

void IOffsetScanAlgo::OnScanFinished()
{
	HandleAllDisp();

	SyncFilteredResults();

	if (mTryInterpret)
		HandleInterpretation();

	if (mParent)
		mParent->OnScanFinished();
}

void IOffsetScanAlgo::SyncFilteredResults()
{
	mFilteredResults.clear();

	for (uintptr_t u : mResults)
		mFilteredResults.insert(u);

	mResults.clear();

	for (auto u : mFilteredResults)
		mResults.push_back(u);
}

const std::unordered_set<uintptr_t>& IOffsetScanAlgo::getResults()
{
	return mFilteredResults;
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

/*
Expecting mResults array to contain offsets of the mBase, where thi are candidates to be interpreted
in the case that the final results arent interpretable, the hte offset will be discarded, at the end, 
the function will fill the mResults with unique properly interpreted results
*/
void IOffsetScanAlgo::HandleInterpretation()
{
	std::vector<unsigned char*> candidadtes;

	for (uintptr_t& r : mResults)
		candidadtes.push_back((unsigned char*)mBuffer + r);

	mResults.clear();

	for (unsigned char* c : candidadtes)
	{
		uintptr_t disp = 0x0;

		if (getCapstoneHelper()->InstDisasmTryGetDisp(c, disp) == false)
		{
			auto sig = mParent->getSignature();
			printf("Unable to resolve \"%s\" candidate \"0x%08X\" result Interpretation\n", sig.c_str(), c - (unsigned char*)mBuffer);
			continue;
		}

		mResults.push_back(disp);
	}

	SyncFilteredResults();
}

void IOffsetScanAlgo::setBufferInfo(const char* buff, size_t buffSz)
{
	mBuffer = buff;
	mBuffSize = buffSz;
}

std::string IOffsetScanAlgo::getCapstoneMode()
{
	return mCapstoneMode;
}

ICapstoneHelper* IOffsetScanAlgo::getCapstoneHelper()
{
	return mParent->getCapstoneHelper();;
}
