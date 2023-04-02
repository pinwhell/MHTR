#pragma once

#include "IScanListener.h"
#include <vector>
#include "JsonValueWrapper.h"
#include "ContainerDisplacer.h"
#include "IChild.h"

class FutureOffset;

class IOffsetScanAlgo : public IScanListener, public IChild<FutureOffset>
{
protected:
	const char* mBuffer;
	size_t mBuffSize;

	std::vector<uintptr_t> mResults;
	JsonValueWrapper mAlgoMetadata;


	int64_t mMainDisp;


public:
	virtual bool Init();
	virtual void IgniteScan();
	virtual void OnScanFinished();
	const std::vector<uintptr_t>& getResults();
	void setAlgoMetadata(const JsonValueWrapper& metadata);

	void HandleAllDisp();

	void setBufferInfo(const char* buff, size_t buffSz);
};

