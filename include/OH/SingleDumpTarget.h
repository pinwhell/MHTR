#pragma once
#include "IDumpTarget.h"
#include "HardcodedOffsetInfo.h"
#include "IFutureResult.h"
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
	std::unordered_map<IFutureResult*, std::unique_ptr<IFutureResult>> mFutureResults;
	std::unordered_map<std::string, IFutureResult*> mFutureResultsByName;
	std::unordered_map<std::string, ICapstoneHelper*> mCapstoneHelpers;
	std::string mTargetMetadataPath;
	JsonValueWrapper mTargetMetadataRoot;
	std::string mTargetBinaryPath;
	std::string mBinFormatStr;

	std::vector<unsigned char> mTargetBinary;
	std::unique_ptr<IBinaryFormat> mBinFormat;
	std::unordered_set<std::string> mAllCapstoneNeededModes;

public:
	bool Init() override;

	bool LoadMetadata();
	bool InitAllMetadata();

	void AddFutureResult(std::unique_ptr<IFutureResult>& futureResult);
	void RemoveFutureResult(IFutureResult* offset);

	void ComputeAll();
	void DispatchFinishEventAll();

	std::string getCategoryName();

	std::string getCategoryObjectName();

	void ReportHppIncludes();
	void WriteHppStaticDeclsDefs();
	void WriteHppDynDecls();
	void WriteHppDynDefs();
	void BeginStruct();
	void EndStruct();

	HeaderFileManager* getHppWriter();
	ICapstoneHelper* getCapstoneHelper(const std::string& mode);
	JsonValueWrapper* getResultJson();
	IFutureResult* getFutureResultByName(const std::string& name);
	void LinkFutureResultWithName(const std::string& name, IFutureResult* futureResult);
	void ReportCapstoneNeededMode(const std::string& mode);

	void ComputeJsonResult();
};

