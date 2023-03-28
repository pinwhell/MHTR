#pragma once

#include <string>
#include <cstdint>

#define ERR_INVALID_OFFSET ((uint64_t)0xFFFFFFFFFFFFFFFF)

class OffsetInfo
{
private:
	std::string mName;
	std::string mComment; // If there is no comment available then this will be empty
	uint64_t mFinalOffset; // this denotes the Actual Result, if there is no offset, this will

public:
	OffsetInfo();

	void setName(const std::string& name);
	void setComment(const std::string& comment);
	void setFinalOffset(uint64_t off);

	const std::string& getName();
	const std::string& getComment();
	uint64_t getFinalOffset();
};

