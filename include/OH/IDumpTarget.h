#pragma once

#include "ICapstoneHelper.h"
#include "CapstoneHelperProvider.h"
#include <memory>
#include "JsonValueWrapper.h"
#include "IJsonAccesor.h"

class TargetManager;

class IDumpTarget
{
protected:
	JsonValueWrapper mDumpTargetDesc;
	TargetManager* mTargetMgr;
public:
	void setTargetManager(TargetManager* pTarget);
	virtual bool Init() = 0;
	virtual void ComputeAll() = 0;
	void setDumpTargetDescJson(const JsonValueWrapper& desc);
};

