#include "FutureOffsetResultInfo.h"

#include "StringHelper.h"

FutureOffsetResultInfo::FutureOffsetResultInfo()
{
	setFinalOffset(0x0);
	mFinalOffset = ERR_INVALID_OFFSET;
}

std::string FutureOffsetResultInfo::getCppDataType()
{
	return "uintptr_t";
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



