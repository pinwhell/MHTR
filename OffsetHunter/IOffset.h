#pragma once

#include "OffsetInfo.h"
#include "JsonValueWrapper.h"
#include "IChild.h"
#include "IJsonAccesor.h"

class SingleDumpTarget;
class TargetManager;

class IOffset : public IChild<SingleDumpTarget>
{
protected:
	OffsetInfo mOffsetInfo;

	// the buffer info i will be finded on
	const char* mBuffer;
	size_t mBuffSize;
	TargetManager* mTargetMgr;

public:

	IOffset();

	virtual bool Init();
	virtual void ComputeOffset() = 0;

	void setTargetManager(TargetManager* pTarget);
	TargetManager* getTargetManager();

	IJsonAccesor* getJsonAccesor();
	bool getDumpDynamic();

	void setMetadata(const JsonValueWrapper& metadata);

	std::string getName();

	void setBufferInfo(const char* buff, size_t buffSz);
};

