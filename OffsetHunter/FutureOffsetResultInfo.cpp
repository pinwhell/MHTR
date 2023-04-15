#include "FutureOffsetResultInfo.h"

#include "StringHelper.h"

#include "IFutureResult.h"
#include "SingleDumpTarget.h"

FutureOffsetResultInfo::FutureOffsetResultInfo()
{
	setFinalOffset(0x0);
	mFinalOffset = ERR_INVALID_OFFSET;
}

std::string FutureOffsetResultInfo::getCppDataType()
{
	return "uintptr_t";
}

std::string FutureOffsetResultInfo::getCppDefaultRvalue()
{
	return "0x0";
}

void FutureOffsetResultInfo::setFinalOffset(uint64_t off)
{
	mFinalOffset = off;
	mFinalObfOffset = mFinalOffset ^ mObfKey;
	mStaticResult->setValue(StringHelper::ToHexString(mFinalOffset));
}

uint64_t FutureOffsetResultInfo::getFinalOffset()
{
	return mFinalOffset == ERR_INVALID_OFFSET ? 0 : mFinalOffset;
}

uint64_t FutureOffsetResultInfo::getFinalObfOffset()
{
	return mFinalObfOffset;
}

void FutureOffsetResultInfo::WriteHppStaticDeclsDefs()
{
	if (mFinalOffset == ERR_INVALID_OFFSET)
		return;

	IFutureResultInfo::WriteHppStaticDeclsDefs();
}

void FutureOffsetResultInfo::WriteHppDynDecls()
{
	if (mFinalOffset == ERR_INVALID_OFFSET)
		return;

	IFutureResultInfo::WriteHppDynDecls();
}

void FutureOffsetResultInfo::WriteHppDynDefs()
{
	if (mFinalOffset == ERR_INVALID_OFFSET)
		return;

	IFutureResultInfo::WriteHppDynDefs();
}

void FutureOffsetResultInfo::OnParentTargetFinish()
{
	if (JSON_ASSERT(getMetadata(), "combine") == false)
		return;

	JsonValueWrapper combineWithNames = getMetadata()["combine"];

	if (combineWithNames.isArray() == false)
		return;

	for (uint32_t i = 0; i < combineWithNames.size(); i++)
	{
		std::string combiningWith = combineWithNames[i].asString();
		IFutureResult* curr = getParent()->getParent()->getFutureResultByName(combiningWith);

		if (curr == nullptr)
		{
			printf("\"%s\" trying to combine with a non existing offset \"%s\"\n", getUidentifier().c_str(), combiningWith.c_str());
			continue;
		}

		if (curr->ResultWasSucessfull() == false)
		{
			printf("\"%s\" trying to combine with a non computed offset \"%s\"\n", getUidentifier().c_str(), combiningWith.c_str());
			continue;
		}

		if (curr->ResultWasSucessfull() == false)
		{
			printf("\"%s\" trying to combine with a non computed offset \"%s\"\n", getUidentifier().c_str(), combiningWith.c_str());
			continue;
		}

		if(FutureOffsetResultInfo* o = dynamic_cast<FutureOffsetResultInfo*>(curr->getFutureResultInfo()))
			setFinalOffset(getFinalOffset() + o->getFinalOffset());
		else 
		{
			printf("\"%s\" trying to combine with a non combinable future result \"%s\"\n", getUidentifier().c_str(), combiningWith.c_str());
			continue;
		}		
	}
}



