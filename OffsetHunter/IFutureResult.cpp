#include "IFutureResult.h"
#include "TargetManager.h"

IFutureResult::IFutureResult()
{
	mIFutureResultInfo.setParent(this);
	mNeedCapstone = false;
}

bool IFutureResult::Init()
{
	if (mIFutureResultInfo.Init() == false)
		return false;

	mParent->LinkFutureResultWithName(mIFutureResultInfo.getName(), this);

	return true;
}

void IFutureResult::setTargetManager(TargetManager* pTarget)
{
	mTargetMgr = pTarget;
}

TargetManager* IFutureResult::getTargetManager()
{
	return mTargetMgr;
}

IJsonAccesor* IFutureResult::getJsonAccesor()
{
	return mTargetMgr->getJsonAccesor();
}

bool IFutureResult::getDumpDynamic()
{
	return mTargetMgr->getDumpDynamic();
}

void IFutureResult::setMetadata(const JsonValueWrapper& metadata)
{
	mIFutureResultInfo.setMetadata(metadata);
}

std::string IFutureResult::getName()
{
	return mIFutureResultInfo.getName();
}

std::string IFutureResult::getSignature()
{
	return mIFutureResultInfo.getUidentifier();
}

void IFutureResult::setBufferInfo(const char* buff, size_t buffSz)
{
	mBuffer = buff;
	mBuffSize = buffSz;
}

void IFutureResult::WriteHppStaticDeclsDefs()
{
	mIFutureResultInfo.WriteHppStaticDeclsDefs();
}

void IFutureResult::WriteHppDynDecls()
{
	mIFutureResultInfo.WriteHppDynDecls();
}

void IFutureResult::WriteHppDynDefs()
{
	mIFutureResultInfo.WriteHppDynDefs();
}

HeaderFileManager* IFutureResult::getHppWriter()
{
	return mParent->getHppWriter();
}

bool IFutureResult::getNeedCapstoneHelper()
{
	return mNeedCapstone;
}

ICapstoneHelper* IFutureResult::getCapstoneHelper()
{
	return mParent->getCapstoneHelper();
}

JsonValueWrapper* IFutureResult::getResultJson()
{
	return mParent->getResultJson();
}

ObfuscationManager* IFutureResult::getObfuscationManager()
{
	return mTargetMgr->getObfuscationManager();
}

IFutureResultInfo* IFutureResult::getFutureResultInfo()
{
	return &mIFutureResultInfo;
}

void IFutureResult::OnParentTargetFinish()
{
	mIFutureResultInfo.OnParentTargetFinish();
}

void IFutureResult::ComputeJsonResult()
{}

bool IFutureResult::WasComputed()
{
	return mIFutureResultInfo.WasComputed();
}
