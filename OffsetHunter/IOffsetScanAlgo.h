#pragma once

#include "IScanListener.h"
#include <vector>
#include "JsonValueWrapper.h"
#include "ContainerDisplacer.h"
#include "IChild.h"
#include <unordered_set>

class ICapstoneHelper;
class FutureOffset;

class IOffsetScanAlgo : public IScanListener, public IChild<FutureOffset>
{
protected:
	const char* mBuffer;
	size_t mBuffSize;

	std::vector<uintptr_t> mResults;
	std::unordered_set<uintptr_t> mFilteredResults;
	JsonValueWrapper mAlgoMetadata;
	int64_t mMainDisp;
	bool mTryInterpret;
	std::string mCapstoneMode;

public:

	virtual bool Init();
	virtual void IgniteScan();
	virtual void OnScanFinished();
	void SyncFilteredResults();
	const std::unordered_set<uintptr_t>& getResults();
	void setAlgoMetadata(const JsonValueWrapper& metadata);

	void HandleAllDisp();
	void HandleInterpretation();
	void setBufferInfo(const char* buff, size_t buffSz);
	std::string getCapstoneMode();
	ICapstoneHelper* getCapstoneHelper();
};

