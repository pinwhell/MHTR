#pragma once

#include <string>
#include <cstdint>
#include "JsonValueWrapper.h"

#define ERR_INVALID_OFFSET ((uint64_t)0xFFFFFFFFFFFFFFFF)

class OffsetInfo
{
private:
	std::string mName;
	std::string mComment; // If there is no comment available then this will be empty
	uint64_t mFinalOffset; // this denotes the Actual Result, if there is no offset, this will
	JsonValueWrapper mMetadata;

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
};

