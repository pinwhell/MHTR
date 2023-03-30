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
	std::vector<uint64_t> mResults;
	JsonValueWrapper mAlgoMetadata;

	ContainerDisplacer<std::vector<uint64_t>> mDisplacer; 
	// i will be used to displace all of the results


public:
	virtual bool Init();
	virtual void IgniteScan();
	virtual void OnScanFinished();
	const std::vector<uint64_t>& getResults();
	void setAlgoMetadata(const JsonValueWrapper& metadata);
	void setParent(FutureOffset* parent);

	void HandleAllDisp();

	void setBufferInfo(const char* buff, size_t buffSz);
};

