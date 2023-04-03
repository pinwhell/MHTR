#pragma once

#include "SingleDumpTarget.h"
#include "JsonValueWrapper.h"
#include <string>
#include <unordered_map>
#include "IChild.h"

struct HeaderFileManager;

class DumpTargetGroup : public IDumpTarget, public IChild<TargetManager>
{
private:
	std::string mMacro;
	std::string mTargetJsonPath;
	std::unordered_map<SingleDumpTarget*, std::unique_ptr<SingleDumpTarget>> mTargets;
	std::string mOutputJsonName;

public:

	bool InitAllTargets();
	bool Init() override;
	void ComputeAll() override;

	void AddTarget(std::unique_ptr<SingleDumpTarget>& target);
	void RemoveTarget(SingleDumpTarget* target);
	void setTargetJsonPath(const std::string& path);

	bool ReadAllTarget();

	void WriteHppStaticDeclsDefs();
	void WriteHppDynDecls();
	void WriteHppDynDefs();
	void MacroBegin();
	void MacroEnd();
	HeaderFileManager* getHppWriter();
};

