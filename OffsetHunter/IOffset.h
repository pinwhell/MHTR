#pragma once

#include "OffsetInfo.h"
#include "JsonValueWrapper.h"

class SingleDumpTarget;

class IOffset
{
protected:
	OffsetInfo mOffsetInfo;
	SingleDumpTarget* mParent;

public:
	virtual bool Init();
	virtual void ComputeOffset() = 0;

	void setMetadata(const JsonValueWrapper& metadata);
	void setParent(SingleDumpTarget* parent);
};

