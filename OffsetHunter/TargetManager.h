#pragma once

#include <unordered_map>
#include "IDumpTarget.h"
#include <string>
#include "JsonValueWrapper.h"

class TargetManager
{
private:
	std::unordered_map<IDumpTarget*, std::unique_ptr<IDumpTarget>> mAllTargets;
	std::string mDumpTargetsPath;
	JsonValueWrapper mDumpTargetsRoot;
public:

	bool Init();
	bool InitAllTargets();
	void ComputeAll();

	void RemoveTarget(IDumpTarget* target);
	void AddTarget(std::unique_ptr<IDumpTarget>& target);

	void setDumpTargetPath(const std::string& path);

	bool ReadAllTargets();

	bool HandleTargetGroupJson(const JsonValueWrapper& targetGroupRoot);
};

