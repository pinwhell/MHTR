#include "OffsetInfo.h"
#include "StaticHasher.h"

OffsetInfo::OffsetInfo()
{
	mFinalOffset = ERR_INVALID_OFFSET;
	mName = "";
	mComment = "";
}

bool OffsetInfo::Init()
{
	if (JSON_ASSERT_STR_EMPTY(mMetadata, "name") == false)
	{
		printf("Cant find \"name\" field");
		return false;
	}

	mName = mMetadata.get<std::string>("name", "");
	mComment = mMetadata.get<std::string>("comment", "");
	mNameHash = std::to_string(fnv1a_32(mName.c_str(), mName.size()));

	return true;
}

void OffsetInfo::setName(const std::string& name)
{
	mName = name;
}

void OffsetInfo::setComment(const std::string& comment)
{
	mComment = comment;
}

void OffsetInfo::setFinalOffset(uint64_t off)
{
	mFinalOffset = off;
}

const std::string& OffsetInfo::getName()
{
	return mName;
}

const std::string& OffsetInfo::getComment()
{
	return mComment;
}

uint64_t OffsetInfo::getFinalOffset()
{
	return mFinalOffset;
}

void OffsetInfo::setMetadata(const JsonValueWrapper& metadata)
{
	mMetadata = metadata;
}

const JsonValueWrapper& OffsetInfo::getMetadata()
{
	return mMetadata;
}

std::string OffsetInfo::getNameHashStr()
{
	return mNameHash;
}
