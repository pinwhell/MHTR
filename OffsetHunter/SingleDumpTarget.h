#pragma once
#include "IDumpTarget.h"
#include "HardcodedOffsetInfo.h"
#include "IOffset.h"
#include <string>
#include <unordered_map>
#include "JsonValueWrapper.h"
#include "IChild.h"
#include "IBinaryFormat.h"

class DumpTargetGroup;
struct HeaderFileManager;

class SingleDumpTarget : public IDumpTarget, public IChild<DumpTargetGroup>
{
private:

	std::string mCategoryName;
	std::string mCategoryObjName; // by default "m" + mCategoryName
	std::unordered_map<IOffset*, std::unique_ptr<IOffset>> mOffsets;
	ICapstoneHelper* mCapstoneHelper;
	std::string mTargetMetadataPath;
	JsonValueWrapper mTargetMetadataRoot;
	std::string mTargetBinaryPath;

	std::vector<unsigned char> mTargetBinary;
	std::unique_ptr<IBinaryFormat> mBinFormat;
	bool mNeedCapstone;

public:

	SingleDumpTarget();

	bool Init() override;

	bool LoadMetadata();
	bool InitAllMetadata();

	void AddOffset(std::unique_ptr<IOffset>& offset);
	void RemoveOffset(IOffset* offset);

	void ComputeAll();

	std::string getCategoryName();

	std::string getCategoryObjectName();

	void WriteHppStaticDeclsDefs();
	void WriteHppDynDecls();
	void WriteHppDynDefs();
	void BeginStruct();
	void EndStruct();
	bool getNeedCapstone();

	HeaderFileManager* getHppWriter();
};

