#include "DumpTargetGroup.h"

bool DumpTargetGroup::InitAllTargets()
{
    for (auto& kv : mTargets)
    {
        if (kv.first->Init() == false)
            return false;
    }

    return true;
}

bool DumpTargetGroup::Init()
{
    if (JSON_IS_MEMBER(mDumpTargetDesc, "targets") == false)
        return false;

    if (ReadAllTarget() == false)
        return false;

    if (InitAllTargets() == false)
        return false;

    return true;
}

void DumpTargetGroup::ComputeAll()
{
    for (auto& kv : mTargets)
        kv.first->ComputeAll();
}

void DumpTargetGroup::AddTarget(std::unique_ptr<SingleDumpTarget>& target)
{
    SingleDumpTarget* pTarget = target.get();

    if (mTargets.find(pTarget) != mTargets.end())
        return;

    mTargets[pTarget] = std::move(target);
}

void DumpTargetGroup::RemoveTarget(SingleDumpTarget* target)
{
    if (mTargets.find(target) == mTargets.end())
        return;

    mTargets.erase(target);
}

bool DumpTargetGroup::ReadAllTarget()
{
    JsonValueWrapper targets = mDumpTargetDesc["targets"];

    if (targets.isArray() == false)
        return false;

    for (size_t i = 0; i < targets.size(); i++)
    {
        JsonValueWrapper curr(targets[i]);

        if (curr.isObject() != true)
            continue;

        std::unique_ptr<SingleDumpTarget> dumpTarget = std::make_unique<SingleDumpTarget>();

        dumpTarget->setDumpTargetDescJson(curr);

        AddTarget(dumpTarget);
    }

    return true;
}
