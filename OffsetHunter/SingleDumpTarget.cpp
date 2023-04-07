#include "SingleDumpTarget.h"
#include "FileHelper.h"
#include "OffsetClassifier.h"
#include <ThreadPool.h>
#include "DumpTargetGroup.h"
#include "HPPManager.h"
#include "BinaryFormatClassifier.h"
#include "TargetManager.h"

SingleDumpTarget::SingleDumpTarget()
{
	mNeedCapstone = false;
}

bool SingleDumpTarget::Init()
{
	if (JSON_ASSERT_STR_EMPTY(mDumpTargetDesc, "name") == false)
	{
		printf("Target Doesnt Contain Name or is Empty\n");
		return false;
	}

	mCategoryName = mDumpTargetDesc.get("name", "");
	mCategoryObjName = "m" + mCategoryName; // By default

	if (JSON_ASSERT_STR_EMPTY(mDumpTargetDesc, "dataset_path") == false)
	{
		printf("\"%s\" Target cant find \"dataset_path\" or is empty\n", mCategoryName.c_str());
		return false;
	}

	if (JSON_ASSERT_STR_EMPTY(mDumpTargetDesc, "bin_path") == false)
	{
		printf("\"%s\" Target cant find \"bin_path\" or is empty\n", mCategoryName.c_str());
		return false;
	}

	mTargetMetadataPath = mDumpTargetDesc.get<std::string>("dataset_path", "");
	mTargetBinaryPath = mDumpTargetDesc.get<std::string>("bin_path", "");
	mBinFormatStr = mDumpTargetDesc.get<std::string>("bin_format", "");

	if (FileHelper::IsValidFilePath(mTargetMetadataPath, true, true) == false)
		return false;

	if (FileHelper::IsValidFilePath(mTargetBinaryPath, true, true) == false)
		return false;

	if (JsonHelper::File2Json(mTargetMetadataPath, mTargetMetadataRoot) == false)
		return false;

	if (FileHelper::ReadFileBinary(mTargetBinaryPath, mTargetBinary) == false)
	{
		printf("\"%s\" Target cant load \"%s\"\n", mCategoryName.c_str(), mTargetBinaryPath.c_str());
		return false;
	}

	BinaryFormatClassifier::Classify(mBinFormatStr, mBinFormat, mTargetBinary.data());

	if (LoadMetadata() == false)
	{
		printf("\"%s\" Target with invalid metadata \"%s\" format\n", mCategoryName.c_str(), mTargetMetadataPath.c_str());
		return false;
	}

	if (InitAllMetadata() == false)
		return false;

	if (getNeedCapstone() == true)
	{
		if (mBinFormat->MakeCapstoneHelper(mTargetMgr->getCapstoneHelperProvider(), &mCapstoneHelper) == false)
		{
			printf("\"%s\" Needs a capstone helper, but it fail to create one, maybe the file format is incorrect\n", mTargetBinaryPath.c_str());
			return false;
		}

		if (mCapstoneHelper->Init() == false)
		{
			printf("\"%s\" Needs a capstone helper, but it fail to initialize one\n", mTargetBinaryPath.c_str());
			return false;
		}

		mCapstoneHelper->setBaseAddress((unsigned char*)mTargetBinary.data());
		mCapstoneHelper->setBaseSize(mTargetBinary.size());
	}

	//printf("%s Need Capstone: %s\n\n", mCategoryName.c_str(), mNeedCapstone ? "Yes" : "No");

	return true;
}

bool SingleDumpTarget::LoadMetadata()
{
	if (mTargetMetadataRoot.isArray() == false)
		return false;

	for (size_t i = 0; i < mTargetMetadataRoot.size(); i++)
	{
		JsonValueWrapper curr = mTargetMetadataRoot[i];
		std::unique_ptr<IOffset> currOff; OffsetClassifier::Classify(curr, currOff);

		currOff->setParent(this);
		currOff->setBufferInfo((const char*)mTargetBinary.data(), mTargetBinary.size());
		currOff->setTargetManager(mTargetMgr);

		AddOffset(currOff);
	}

	return true;
}

bool SingleDumpTarget::InitAllMetadata()
{
	for (auto& currOff : mOffsets)
	{
		if (currOff.first->Init() == false)
			return false;

		mNeedCapstone = currOff.first->getNeedCapstoneHelper() || mNeedCapstone;
	}

	return true;
}

void SingleDumpTarget::AddOffset(std::unique_ptr<IOffset>& offset)
{
	auto* pCurr = offset.get();

	if (mOffsets.find(pCurr) != mOffsets.end())
		return;

	mOffsets[pCurr] = std::move(offset);
}

void SingleDumpTarget::RemoveOffset(IOffset* offset)
{
	if (mOffsets.find(offset) != mOffsets.end())
		return;

	mOffsets.erase(offset);
}

void SingleDumpTarget::ComputeAll()
{
	ThreadPool tp;

	for (auto& kv : mOffsets)
	{
		tp.enqueue([&](IOffset* pOff) {
			pOff->ComputeOffset();
			}, kv.second.get());
	}
		
}

std::string SingleDumpTarget::getCategoryName()
{
	return mCategoryName;
}

std::string SingleDumpTarget::getCategoryObjectName()
{
	return mCategoryObjName;
}

void SingleDumpTarget::WriteHppStaticDeclsDefs()
{
	BeginStruct();

	for (auto& currOff : mOffsets)
		currOff.first->WriteHppStaticDeclsDefs();

	EndStruct();
}

void SingleDumpTarget::WriteHppDynDecls()
{
	BeginStruct();

	for (auto& currOff : mOffsets)
		currOff.first->WriteHppDynDecls();
	
	EndStruct();
}

void SingleDumpTarget::WriteHppDynDefs()
{
	for (auto& currOff : mOffsets)
		currOff.first->WriteHppDynDefs();
}

void SingleDumpTarget::BeginStruct()
{
	mParent->getHppWriter()->BeginStruct(mCategoryName);
}

void SingleDumpTarget::EndStruct()
{
	mParent->getHppWriter()->EndStruct(mCategoryName, { mCategoryObjName }); // by default mCategoryObjName = "m" + mCategoryName
}

bool SingleDumpTarget::getNeedCapstone()
{
	return mNeedCapstone;
}

HeaderFileManager* SingleDumpTarget::getHppWriter()
{
	return mParent->getHppWriter();
}

ICapstoneHelper* SingleDumpTarget::getCapstoneHelper()
{
	return mCapstoneHelper;
}
