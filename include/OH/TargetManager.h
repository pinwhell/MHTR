#pragma once

#include <unordered_map>
#include "DumpTargetGroup.h"
#include <string>
#include "JsonValueWrapper.h"
#include "HPPManager.h"
#include "IChild.h"
#include "IJsonAccesor.h"
#include "ObfuscationManager.h"
#include <OH/ConfigManager.h>

class OffsetHunter;

class TargetManager : public IChild<OffsetHunter>
{
private:
	std::unordered_map<DumpTargetGroup*, std::unique_ptr<DumpTargetGroup>> mAllTargets; // For now just supporting DumpTargetGroup

	std::string mDynamicJsonObjName; // by default "obj"
	std::string mDynamicOffsetSetterFuncName; // by default "Set"

	std::unordered_set<std::string> mIncludes;

	JsonValueWrapper mDumpTargetsRoot;

	std::unique_ptr<HeaderFileManager> mHppWriter;
	std::unique_ptr<IJsonAccesor> mJsonAccesor;
	std::unique_ptr<ObfuscationManager> mObfucationManager;

	ConfigManager* mConfigMgr;

	bool SaveJson();
	bool SaveHppCompileTime();
	bool SaveHppRuntime();

public:
	TargetManager();

	bool Init();
	bool InitAllTargets();
	void ComputeAll();
	bool SaveResults();

	void setConfigManager(ConfigManager* configMgr);
	ConfigManager* getConfigManager();

	void RemoveTarget(DumpTargetGroup* target);
	void AddTarget(std::unique_ptr<DumpTargetGroup>& target);

	bool ReadAllTargets();

	bool HandleTargetGroupJson(const JsonValueWrapper& targetGroupRoot);

	HeaderFileManager* getHppWriter();

	void setJsonAccesor(std::unique_ptr<IJsonAccesor>&& accesor);
	IJsonAccesor* getJsonAccesor();

	void setDynamicOffsetSetterFuncName(const std::string& dynamicOffsetSetterFuncName);

	void WriteHppIncludes();
	void WriteHppStaticDeclsDefs();
	void WriteHppDynDecls();
	void WriteHppDynDefs();
	CapstoneHelperProvider* getCapstoneHelperProvider();
	ObfuscationManager* getObfuscationManager();

	void AddInclude(const std::string& toInclude);
};

