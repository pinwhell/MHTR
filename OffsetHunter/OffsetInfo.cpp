#include "OffsetInfo.h"
#include "StaticHasher.h"
#include "CppLValueRValueWrapper.h"
#include "CppNestedLValueRValueWrapper.h"
#include "IOffset.h"
#include "SingleDumpTarget.h"
#include "HPPManager.h"
#include "StringHelper.h"

OffsetInfo::OffsetInfo()
{
	mStaticResult = std::make_unique<CppLValueRValueWrapper>(); // Will be used for Declaring-defining the static result
	mDynamicResult = std::make_unique<CppNestedLValueRValueWrapper>(); // Will be used for declaring and defining the dynamic result

	setFinalOffset(0x0);
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
	mUIdentifier = mParent->getParent()->getCategoryName() + "::" + mName;
	mComment = mMetadata.get<std::string>("comment", "");

	mStaticResult->setType("uintptr_t");	// For now, in the future, it will polomorifcly 
											// select between example std::string, or any other
	mStaticResult->setName(mName);
	mStaticResult->setValue("0x0");

	if (mParent->getDumpDynamic())
	{
		mDynamicResult->setType("uintptr_t");
		mDynamicResult->PushParentName(mParent->getParent()->getCategoryObjectName());
		mDynamicResult->setName(mName);

		mUIdentifier = mDynamicResult->getFullName();   // This will chain all, and will get the full name
														// for example: mA.mB.mC.mD
														// so this way can get a unique identifier for this variable

		mUIDHash = std::to_string((uint32_t)fnv1a_32(mUIdentifier.c_str(), mUIdentifier.size()));

		mDynamicResult->setValue(mParent->getJsonAccesor()->genGetUInt(mUIDHash, mObfKey));
	}

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
	mFinalObfOffset = mFinalOffset ^ mObfKey;
	mStaticResult->setValue(StringHelper::ToHexString(mFinalOffset));
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

uint64_t OffsetInfo::getFinalObfOffset()
{
	return mFinalObfOffset;
}

void OffsetInfo::setMetadata(const JsonValueWrapper& metadata)
{
	mMetadata = metadata;
}

const JsonValueWrapper& OffsetInfo::getMetadata()
{
	return mMetadata;
}

std::string OffsetInfo::getUIDHashStr()
{
	return mUIDHash;
}

void OffsetInfo::WriteHppStaticDeclsDefs()
{
	if (mFinalOffset == ERR_INVALID_OFFSET)
		return;

	getHppWriter()->AppendLineOfCode(mStaticResult->ComputeDefinitionAndDeclaration(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void OffsetInfo::WriteHppDynDecls()
{
	if (mFinalOffset == ERR_INVALID_OFFSET)
		return;

	getHppWriter()->AppendLineOfCode(mDynamicResult->ComputeDeclaration(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void OffsetInfo::WriteHppDynDefs()
{
	if (mFinalOffset == ERR_INVALID_OFFSET)
		return;

	getHppWriter()->AppendLineOfCode(mDynamicResult->ComputeDefinition(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

HeaderFileManager* OffsetInfo::getHppWriter()
{
	return mParent->getHppWriter();
}

bool OffsetInfo::getNeedShowComment()
{
	return mComment.empty() == false;
}

std::string OffsetInfo::getUidentifier()
{
	return mUIdentifier;
}
