#pragma once

#include "OffsetInfo.h"
#include "JsonValueWrapper.h"
#include "IChild.h"

class SingleDumpTarget;

class IOffset : public IChild<SingleDumpTarget>
{
protected:
	OffsetInfo mOffsetInfo;

	// the buffer info i will be finded on
	const char* mBuffer;
	size_t mBuffSize;

public:
	virtual bool Init();
	virtual void ComputeOffset() = 0;

	void setMetadata(const JsonValueWrapper& metadata);

	std::string getName();

	void setBufferInfo(const char* buff, size_t buffSz);
};

