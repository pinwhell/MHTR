#include "IOffset.h"
#include "JsonCppAcessor.h"

bool IOffset::Init()
{
	if (mOffsetInfo.Init() == false)
		return false;

	return true;
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