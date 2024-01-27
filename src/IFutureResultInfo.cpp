#include <OH/IFutureResultInfo.h>
#include <OH/StaticHasher.h>
#include <OH/CppLValueRValueWrapper.h>
#include <OH/CppNestedLValueRValueWrapper.h>
#include <OH/IFutureResult.h>
#include <OH/SingleDumpTarget.h>
#include <OH/HPPManager.h>
#include <OH/StringHelper.h>
#include <OH/ObfuscationManager.h>
#include <OH/FutureOffsetResultInfo.h>

IFutureResultInfo::IFutureResultInfo()
	: mSaltKey(0)
	, mObfKey(0)
{
	mStaticResult = std::make_unique<CppLValueRValueWrapper>(); // Will be used for Declaring-defining the static result
	mStructMemberAccessor = std::make_unique<CppNestedLValueRValueWrapper>(); // Will be used for declaring and defining the dynamic result

	mName = "";
	mComment = "";
}

bool IFutureResultInfo::Init()
{
	if (JSON_ASSERT_STR_EMPTY(getMetadata(), "name") == false)
	{
		printf("Cant find \"name\" field");
		return false;
	}

	mName = getMetadata().get<std::string>("name", "");
	mUIdentifier = mParent->getParent()->getCategoryName() + "::" + mName;
	mComment = getMetadata().get<std::string>("comment", "");

	mStaticResult->setType(getCppDataType());
	mStaticResult->setName(mName);
	mStaticResult->setValue(getCppDefaultRvalue());

	mStructMemberAccessor->setType(getCppDataType());
	mStructMemberAccessor->PushParentName(mParent->getParent()->getCategoryObjectName());
	mStructMemberAccessor->setName(mName);

	mUIdentifierDynamic = mStructMemberAccessor->getFullName();   // This will chain all, and will get the full name
	// for example: mA.mB.mC.mD
	// so this way can get a unique identifier for this variable

	if (mParent->getIdentifierSalt())
	{
		mSaltKey = getObfuscationManager()->getSaltKey(mUIdentifierDynamic);
		mUIdentifierDynamicSalted = mUIdentifierDynamic + "_" + std::to_string(mSaltKey);
		mUIDHash = std::to_string((uint32_t)fnv1a_32(mUIdentifierDynamicSalted.c_str(), mUIdentifierDynamicSalted.size()));
	} else 
		mUIDHash = std::to_string((uint32_t)fnv1a_32(mUIdentifierDynamic.c_str(), mUIdentifierDynamic.size()));

	if (mParent->getDumpEncrypt())
		mObfKey = getObfuscationManager()->getObfKey(mUIdentifierDynamic);

	if(mParent->getDumpDynamic() || mParent->getDumpRuntime())
		mStructMemberAccessor->setValue(mParent->getJsonAccesor()->genGetUInt(getUniqueIdentifier(), mParent->getDumpEncrypt() ? mObfKey : 0x0));

	mCanPickAnyResult = getMetadata().get<bool>("pick_any_result", false);

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

bool IFutureResultInfo::CanPickAnyResult()
{
	return mCanPickAnyResult;
}

void IFutureResultInfo::WriteHppStaticDeclsDefs()
{
	if (mParent->ResultWasSucessfull() == false)
		return;

	getHppWriter()->AppendLineOfCode(mStaticResult->ComputeDefinitionAndDeclaration(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void IFutureResultInfo::WriteHppDynDecls()
{
	if (mParent->ResultWasSucessfull() == false)
		return;

	getHppWriter()->AppendLineOfCode(mStructMemberAccessor->ComputeDeclaration(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void IFutureResultInfo::WriteHppDef()
{
	if (mParent->ResultWasSucessfull() == false)
		return;

	getHppWriter()->AppendLineOfCode(mStructMemberAccessor->ComputeDefinition(), true, getNeedShowComment() == false);

	if (getNeedShowComment())
	{
		getHppWriter()->AppendTab();
		getHppWriter()->AppendComment(mComment);
	}
}

void IFutureResultInfo::HppRuntimeDecryptionWrite(IJsonAccesor* jsonAccesor)
{
	if (mParent->ResultWasSucessfull() == false)
		return;

	if(mParent->getIdentifierHash()) 
		getHppWriter()->AppendLineOfCode("/* " + (mParent->getIdentifierSalt() ? mUIdentifierDynamicSalted : mUIdentifierDynamic) + " */\t", true, false);

	getHppWriter()->AppendLineOfCode(jsonAccesor->genAssign(getUniqueIdentifier(), jsonAccesor->genGetUInt(getUniqueIdentifier(), mObfKey)), mParent->getIdentifierHash() == false, getNeedShowComment() == false);

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

JsonValueWrapper& IFutureResultInfo::getMetadata()
{
	return mParent->getMetadata();
}

std::string IFutureResultInfo::getUniqueIdentifier()
{
	return mParent->getIdentifierHash() ? getUIDHashStr() : (mParent->getIdentifierSalt() ? mUIdentifierDynamicSalted : mUIdentifierDynamic);
}