#pragma once

#include "SingleDumpTarget.h"
#include "JsonValueWrapper.h"
#include <string>
#include <unordered_map>

class DumpTargetGroup : public IDumpTarget
{
private:
	std::string mMacro;
	std::unordered_map<SingleDumpTarget*, std::unique_ptr<SingleDumpTarget>> mTargets;

public:

	bool InitAllTargets();
	bool Init() override;
	void ComputeAll() override;

	void AddTarget(std::unique_ptr<SingleDumpTarget>& target);
	void RemoveTarget(SingleDumpTarget* target);

	bool ReadAllTarget();
};

