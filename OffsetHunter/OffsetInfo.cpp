#include "OffsetInfo.h"
#include "StaticHasher.h"
#include "CppLValueRValueWrapper.h"
#include "CppNestedLValueRValueWrapper.h"
#include "IOffset.h"
#include "SingleDumpTarget.h"
#include "HPPManager.h"

OffsetInfo::OffsetInfo()
{
	mFinalOffset = ERR_INVALID_OFFSET;
	mName = "";
	mComment = "";

	mStaticResult = std::make_unique<CppLValueRValueWrapper>(); // Will be used for Declaring-defining the static result
	mDynamicResult = std::make_unique<CppNestedLValueRValueWrapper>(); // Will be used for declaring and defining the dynamic result
}

bool OffsetInfo::Init()
{
	if (JSON_ASSERT_STR_EMPTY(mMetadata, "name") == false)
	{
		printf("Cant find \"name\" field");
		return false;
	}

	mName = mMetadata.get<std::string>("name", "");
	mUIdentifier = mParent->getParent()->getCategoryName() + "." + mName;
	mComment = mMetadata.get<std::string>("comment", "");

	mStaticResult->setType("uintptr_t");	// For now, in the future, it will polomorifcly 
											// select between example std::string, or any other
	mStaticResult->setName(mName);
	mStaticResult->setValue("0");

	if (mParent->getDumpDynamic())
	{
		mDynamicResult->setType("uintptr_t");
		mDynamicResult->PushParentName(mParent->getParent()->getCategoryObjectName());
		mDynamicResult->setName(mName);

		mUIdentifier = mDynamicResult->getFullName();   // This will chain all, and will get the full name
														// for example: mA.mB.mC.mD
														// so this way can get a unique identifier for this variable

		mUIDHash = std::to_string(fnv1a_32(mUIdentifier.c_str(), mUIdentifier.size()));

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

std::string OffsetInfo::getUIDHashStr()
{
	return mUIDHash;
}

void OffsetInfo::WriteHppStaticDeclsDefs()
{
	mParent->getHppWriter()->AppendLineOfCode(mStaticResult->ComputeDefinitionAndDeclaration());
}

void OffsetInfo::WriteHppDynDecls()
{
	mParent->getHppWriter()->AppendLineOfCode(mDynamicResult->ComputeDeclaration());
}

void OffsetInfo::WriteHppDynDefs()
{
	mParent->getHppWriter()->AppendLineOfCode(mDynamicResult->ComputeDefinition());
}
