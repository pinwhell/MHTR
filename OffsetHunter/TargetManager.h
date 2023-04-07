#pragma once

#include <unordered_map>
#include "DumpTargetGroup.h"
#include <string>
#include "JsonValueWrapper.h"
#include "HPPManager.h"
#include "IChild.h"
#include "IJsonAccesor.h"

class OffsetHunter;

class TargetManager : public IChild<OffsetHunter>
{
private:
	std::unordered_map<DumpTargetGroup*, std::unique_ptr<DumpTargetGroup>> mAllTargets; // For now just supporting DumpTargetGroup

	std::string mDumpTargetsPath;
	std::string mMainCategoryName;
	std::string mHppOutputPath;
	std::string mGlobalDumpObjName;
	std::string mDumpJsonLibName;
	std::string mDynamicJsonObjName; // by default "obj"
	std::string mDynamicOffsetSetterFuncName; // by default "Set"

	JsonValueWrapper mDumpTargetsRoot;
	std::unique_ptr<HeaderFileManager> mHppWriter;

	std::unique_ptr<IJsonAccesor> mJsonAccesor;

	bool mDumpDynamic;
	bool mDeclareDumpObject;

	bool NeedSaveJson();
	bool SaveJson();
	bool SaveHpp();

public:

	TargetManager();

	bool Init();
	bool InitAllTargets();
	void ComputeAll();
	bool SaveResults();

	void RemoveTarget(DumpTargetGroup* target);
	void AddTarget(std::unique_ptr<DumpTargetGroup>& target);

	void setDumpTargetPath(const std::string& path);
	void setMainCategoryName(const std::string& mainCategoryName);
	void setHppOutputPath(const std::string& outputPath);

	bool ReadAllTargets();

	bool HandleTargetGroupJson(const JsonValueWrapper& targetGroupRoot);

	HeaderFileManager* getHppWriter();

	void setDumpDynamic(bool b);
	void setDeclareGlobalDumpObj(bool b);
	void setGlobalDumpObjectName(const std::string& globalObjName);

	void setJsonAccesor(std::unique_ptr<IJsonAccesor>&& accesor);
	IJsonAccesor* getJsonAccesor();

	void setDumpJsonLibName(const std::string& dumpJsonLibName);
	bool getDumpDynamic();

	void setDynamicOffsetSetterFuncName(const std::string& dynamicOffsetSetterFuncName);

	void WriteHppStaticDeclsDefs();
	void WriteHppDynDecls();
	void WriteHppDynDefs();
	CapstoneHelperProvider* getCapstoneHelperProvider();
};

