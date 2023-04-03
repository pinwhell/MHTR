#include "IDumpTarget.h"

void IDumpTarget::setTargetManager(TargetManager* pTarget)
{
	mTargetMgr = pTarget;
}

void IDumpTarget::setDumpTargetDescJson(const JsonValueWrapper& desc)
{
	mDumpTargetDesc = desc;
}
