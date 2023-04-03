#pragma once

#include <string>
#include <cstdint>
#include "JsonValueWrapper.h"
#include "ILValueRValueWrapper.h"
#include "IChild.h"

#define ERR_INVALID_OFFSET ((uint64_t)0xFFFFFFFFFFFFFFFF)

class IOffset;

class OffsetInfo : public IChild<IOffset>
{ 
private:
	std::string mName;
	std::string mUIdentifier;
	std::string mUIDHash;
	std::string mComment; // If there is no comment available then this will be empty
	uint64_t mFinalOffset; // this denotes the Actual Result, if there is no offset
	JsonValueWrapper mMetadata;
	uint32_t mObfKey;
	std::unique_ptr<ILValueRValueWrapper> mStaticResult;
	std::unique_ptr<ILValueRValueWrapper> mDynamicResult;

public:
	OffsetInfo();

	bool Init();

	void setName(const std::string& name);
	void setComment(const std::string& comment);
	void setFinalOffset(uint64_t off);

	const std::string& getName();
	const std::string& getComment();
	uint64_t getFinalOffset();
	void setMetadata(const JsonValueWrapper& metadata);
	const JsonValueWrapper& getMetadata();
	std::string getUIDHashStr();
};

