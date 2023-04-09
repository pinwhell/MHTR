#pragma once

#include <string>
#include <cstdint>
#include "JsonValueWrapper.h"
#include "ILValueRValueWrapper.h"
#include "INestedLValueRValueWrapper.h"
#include "IChild.h"

#define ERR_INVALID_OFFSET ((uint64_t)0xFFFFFFFFFFFFFFFF)

class IOffset;
struct HeaderFileManager;
class ObfuscationManager;

class OffsetInfo : public IChild<IOffset>
{ 
private:
	std::string mName;
	std::string mUIdentifier;
	std::string mUIdentifierDynamic;
	std::string mUIDHash;
	std::string mComment; // If there is no comment available then this will be empty
	uint64_t mFinalOffset; // this denotes the Actual Result, if there is no offset it will contain ERR_INVALID_OFFSET
	uint64_t mFinalObfOffset; // this denotes the Actual Result obfuscated
	JsonValueWrapper mMetadata;
	uint32_t mObfKey;
	uint32_t mSaltKey;
	std::unique_ptr<ILValueRValueWrapper> mStaticResult;
	std::unique_ptr<INestedLValueRValueWrapper> mDynamicResult; // Why nested? well, basicly we need to do, chainig struct
																// objects to be able to modify/acess the desired offset
																// for ex. mA.mB.mC = 0xXYZ;

public:
	OffsetInfo();

	bool Init();

	void setName(const std::string& name);
	void setComment(const std::string& comment);
	void setFinalOffset(uint64_t off);

	const std::string& getName();
	const std::string& getComment();
	uint64_t getFinalOffset();
	uint64_t getFinalObfOffset();
	void setMetadata(const JsonValueWrapper& metadata);
	const JsonValueWrapper& getMetadata();
	std::string getUIDHashStr();

	void WriteHppStaticDeclsDefs();
	void WriteHppDynDecls();
	void WriteHppDynDefs();

	HeaderFileManager* getHppWriter();

	bool getNeedShowComment();

	std::string getUidentifier();
	ObfuscationManager* getObfuscationManager();
	void OnParentTargetFinish();
	bool WasComputed();
};

