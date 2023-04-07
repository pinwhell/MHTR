#include "IOffset.h"
#include "TargetManager.h"

IOffset::IOffset()
{
	mOffsetInfo.setParent(this);
	mNeedCapstone = false;
}

bool IOffset::Init()
{
	if (mOffsetInfo.Init() == false)
		return false;

	return true;
}

void IOffset::setTargetManager(TargetManager* pTarget)
{
	mTargetMgr = pTarget;
}

TargetManager* IOffset::getTargetManager()
{
	return mTargetMgr;
}

IJsonAccesor* IOffset::getJsonAccesor()
{
	return mTargetMgr->getJsonAccesor();
}

bool IOffset::getDumpDynamic()
{
	return mTargetMgr->getDumpDynamic();
}

void IOffset::setMetadata(const JsonValueWrapper& metadata)
{
	mOffsetInfo.setMetadata(metadata);
}

std::string IOffset::getName()
{
	return mOffsetInfo.getName();
}

void IOffset::setBufferInfo(const char* buff, size_t buffSz)
{
	mBuffer = buff;
	mBuffSize = buffSz;
}

void IOffset::WriteHppStaticDeclsDefs()
{
	mOffsetInfo.WriteHppStaticDeclsDefs();
}

void IOffset::WriteHppDynDecls()
{
	mOffsetInfo.WriteHppDynDecls();
}

void IOffset::WriteHppDynDefs()
{
	mOffsetInfo.WriteHppDynDefs();
}

HeaderFileManager* IOffset::getHppWriter()
{
	return mParent->getHppWriter();
}
