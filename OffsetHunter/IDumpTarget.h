#pragma once

#include "ICapstoneHelper.h"
#include "CapstoneHelperProvider.h"
#include <memory>
#include "JsonValueWrapper.h"

class IDumpTarget
{
protected:
	JsonValueWrapper mDumpTargetDesc;
public:
	virtual bool Init() = 0;
	virtual void ComputeAll() = 0;
	void setDumpTargetDescJson(const JsonValueWrapper& desc);
};

