#include "IOffset.h"
#include "JsonCppAcessor.h"

bool IOffset::Init()
{
	if (mOffsetInfo.Init() == false)
		return false;

	// For now defualt use is JsonCpp Accesor

	mOffsetInfo.setJsonAccesor(std::make_unique<JsonCppAcessor>());
	mOffsetInfo.getJsonAccesor()->setJsonObjectName("obj"); // Default "obj", obj["xyz"].asXyz();
	mOffsetInfo.getJsonAccesor()->setKey(mOffsetInfo.getNameHashStr());

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