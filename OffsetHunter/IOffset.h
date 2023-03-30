#pragma once

#include "OffsetInfo.h"
#include "JsonValueWrapper.h"

class SingleDumpTarget;

class IOffset
{
protected:
	OffsetInfo mOffsetInfo;
	SingleDumpTarget* mParent;

	// the buffer info i will be finded on
	const char* mBuffer;
	size_t mBuffSize;

public:
	virtual bool Init();
	virtual void ComputeOffset() = 0;

	void setMetadata(const JsonValueWrapper& metadata);
	void setParent(SingleDumpTarget* parent);

	std::string getName();

	void setBufferInfo(const char* buff, size_t buffSz);
};

