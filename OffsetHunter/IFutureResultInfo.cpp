#include "IFutureResultInfo.h"
#include "StaticHasher.h"
#include "CppLValueRValueWrapper.h"
#include "CppNestedLValueRValueWrapper.h"
#include "IFutureResult.h"
#include "SingleDumpTarget.h"
#include "HPPManager.h"
#include "StringHelper.h"
#include "ObfuscationManager.h"
#include "FutureOffsetResultInfo.h"

IFutureResultInfo::IFutureResultInfo()
{
	mStaticResult = std::make_unique<CppLValueRValueWrapper>(); // Will be used for Declaring-defining the static result
	mDynamicResult = std::make_unique<CppNestedLValueRValueWrapper>(); // Will be used for declaring and defining the dynamic result

	mName = "";
	mComment = "";
}

bool IFutureResultInfo::Init()
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

		mUIdentifierDynamic = mDynamicResult->getFullName();   // This will chain all, and will get the full name
														// for example: mA.mB.mC.mD
														// so this way can get a unique identifier for this variable


		mObfKey = getObfuscationManager()->getObfKey(mUIdentifierDynamic);
		mSaltKey = getObfuscationManager()->getSaltKey(mUIdentifierDynamic);

		if (mSaltKey != 0)
			mUIdentifierDynamic += "_" + std::to_string(mSaltKey);

		mUIDHash = std::to_string((uint32_t)fnv1a_32(mUIdentifierDynamic.c_str(), mUIdentifierDynamic.size()));

		mDynamicResult->setValue(mParent->getJsonAccesor()->genGetUInt(mUIDHash, mObfKey));
	} else mUIDHash = std::to_string((uint32_t)fnv1a_32(mUIdentifier.c_str(), mUIdentifier.size()));

	return true;
}

void IFutureResultInfo::setName(const std::string& name)
{
	mName = name;
}

void IFutureResultInfo::setComment(const std::string& comment)
{
	mComment = comment;
}

const std::string& IFutureResultInfo::getName()
{
	return mName;
}

const std::string& IFutureResultInfo::getComment()
{
	return mComment;
}

std::string IFutureResultInfo::getUIDHashStr()
{
	return mUIDHash;
}

void IFutureResultInfo::WriteHppStaticDeclsDefs()
{
	getHppWriter()->AppendLineOfCode(mStaticResult->ComputeDefinitionAndDeclaration(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void IFutureResultInfo::WriteHppDynDecls()
{
	getHppWriter()->AppendLineOfCode(mDynamicResult->ComputeDeclaration(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void IFutureResultInfo::WriteHppDynDefs()
{
	getHppWriter()->AppendLineOfCode(mDynamicResult->ComputeDefinition(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

HeaderFileManager* IFutureResultInfo::getHppWriter()
{
	return mParent->getHppWriter();
}

bool IFutureResultInfo::getNeedShowComment()
{
	return mComment.empty() == false;
}

std::string IFutureResultInfo::getUidentifier()
{
	return mUIdentifier;
}

ObfuscationManager* IFutureResultInfo::getObfuscationManager()
{
	return mParent->getObfuscationManager();
}

void IFutureResultInfo::OnParentTargetFinish()
{
	if (JSON_ASSERT(mMetadata, "combine") == false)
		return;

	JsonValueWrapper combineWithNames = mMetadata["combine"];

	if (combineWithNames.isArray() == false)
		return;

	for (uint32_t i = 0; i < combineWithNames.size(); i++)
	{
		std::string combiningWith = combineWithNames[i].asString();
		IFutureResult* curr = mParent->getParent()->getFutureResultByName(combiningWith);

		if (curr == nullptr)
		{
			printf("\"%s\" trying to combine with a non existing offset \"%s\"\n", mUIdentifier.c_str(), combiningWith.c_str());
			continue;
		}

		if (curr->ResultWasSucessfull() == false)
		{
			printf("\"%s\" trying to combine with a non computed offset \"%s\"\n", mUIdentifier.c_str(), combiningWith.c_str());
			continue;
		}

		//setFinalOffset(getFinalOffset() + curr->getFutureResultInfo()->getFinalOffset());
	}
}