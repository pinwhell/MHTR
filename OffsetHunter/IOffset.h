#pragma once

#include "OffsetInfo.h"
#include "JsonValueWrapper.h"
#include "IChild.h"
#include "IJsonAccesor.h"

class SingleDumpTarget;
class TargetManager;
struct HeaderFileManager;
class ICapstoneHelper;

class IOffset : public IChild<SingleDumpTarget>
{
protected:
	OffsetInfo mOffsetInfo;

	// the buffer info i will be finded on
	const char* mBuffer;
	size_t mBuffSize;
	TargetManager* mTargetMgr;
	bool mNeedCapstone;

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
	std::string getSignature();

	void setBufferInfo(const char* buff, size_t buffSz);

	void WriteHppStaticDeclsDefs(); // This structs arround need to be refactored to handle general stuffs, not just offsets,
	void WriteHppDynDecls(); // Code structure is done, just refactoring names, and key specific structures
	void WriteHppDynDefs();

	HeaderFileManager* getHppWriter();

	bool getNeedCapstoneHelper();
	ICapstoneHelper* getCapstoneHelper();
	JsonValueWrapper* getResultJson();
	
	virtual void ComputeJsonResult();
};

