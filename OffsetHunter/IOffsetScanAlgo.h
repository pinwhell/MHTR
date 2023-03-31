#pragma once

#include "IScanListener.h"
#include <vector>
#include "JsonValueWrapper.h"
#include "ContainerDisplacer.h"

class FutureOffset;

class IOffsetScanAlgo : public IScanListener
{
protected:
	const char* mBuffer;
	size_t mBuffSize;

	FutureOffset* mParent;
	std::vector<uintptr_t> mResults;
	JsonValueWrapper mAlgoMetadata;


	int64_t mMainDisp;


public:
	virtual bool Init();
	virtual void IgniteScan();
	virtual void OnScanFinished();
	const std::vector<uintptr_t>& getResults();
	void setAlgoMetadata(const JsonValueWrapper& metadata);
	void setParent(FutureOffset* parent);

	void HandleAllDisp();

	void setBufferInfo(const char* buff, size_t buffSz);
};

