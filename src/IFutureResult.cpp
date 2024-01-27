#include <OH/IFutureResult.h>
#include <OH/TargetManager.h>
#include <atomic>

IFutureResult::IFutureResult()
{
	mResultState = ResultState::NOT_STARTED;
}

std::string IFutureResult::getName()
{
	return mpFutureResultInfo->getName();
}

std::string IFutureResult::getSignature()
{
	return mpFutureResultInfo->getUidentifier();
}

void IFutureResult::ReportHppIncludes()
{
	mpFutureResultInfo->ReportHppIncludes();
}

bool IFutureResult::Init()
{
	mpFutureResultInfo->setParent(this);

	if (mpFutureResultInfo->Init() == false)
		return false;

	mParent->LinkFutureResultWithName(getName(), this);

	return true;
}

void IFutureResult::Compute()
{
	onStartComputing();
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
	return mTargetMgr->getConfigManager()->mDumpDynamic;
}

bool IFutureResult::getDumpRuntime()
{
	return mTargetMgr->getConfigManager()->mDumpRuntime;
}

bool IFutureResult::getDumpEncrypt()
{
	return mTargetMgr->getConfigManager()->mDumpEncrypt;
}

bool IFutureResult::getIdentifierSalt()
{
	return mTargetMgr->getConfigManager()->mIdentifierSalt;
}

bool IFutureResult::getIdentifierHash()
{
	return mTargetMgr->getConfigManager()->mIdentifierHash;
}

void IFutureResult::setMetadata(const JsonValueWrapper& metadata)
{
	mMetadata = metadata;
}

JsonValueWrapper& IFutureResult::getMetadata()
{
	return mMetadata;
}

void IFutureResult::setBufferInfo(const char* buff, size_t buffSz)
{
	mBuffer = buff;
	mBuffSize = buffSz;
}

HeaderFileManager* IFutureResult::getHppWriter()
{
	return mParent->getHppWriter();
}

JsonValueWrapper* IFutureResult::getResultJson()
{
	return mParent->getResultJson();
}

IFutureResultInfo* IFutureResult::getFutureResultInfo()
{
	return mpFutureResultInfo;
}

ObfuscationManager* IFutureResult::getObfuscationManager()
{
	return mTargetMgr->getObfuscationManager();
}

void IFutureResult::OnParentTargetFinish()
{
	mpFutureResultInfo->OnParentTargetFinish();
}

void IFutureResult::WriteHppDynDecls()
{
	mpFutureResultInfo->WriteHppDynDecls();
}

void IFutureResult::WriteHppCompileTimeDefs()
{
	mpFutureResultInfo->WriteHppDef();
}

void IFutureResult::HppRuntimeDecryptionWrite(IJsonAccesor* jsonAccesor)
{
	mpFutureResultInfo->HppRuntimeDecryptionWrite(jsonAccesor);
}

void IFutureResult::WriteHppStaticDeclsDefs()
{
	mpFutureResultInfo->WriteHppStaticDeclsDefs();
}


void IFutureResult::ComputeJsonResult()
{

}

void IFutureResult::setResultState(ResultState newState)
{
	mResultState = newState;
}

void IFutureResult::onStartComputing()
{
	setResultState(ResultState::IN_PROGRESS);
}

void IFutureResult::onSucessfullyComputed()
{
	setResultState(ResultState::FINISH_SUCESS);
}

void IFutureResult::onNotSucessComputing()
{
	setResultState(ResultState::FINISH_INVALID);
}

bool IFutureResult::ResultWasSucessfull()
{
	return mResultState == ResultState::FINISH_SUCESS;
}