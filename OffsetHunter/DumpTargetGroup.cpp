#include "DumpTargetGroup.h"
#include "TargetManager.h"
#include <ThreadPool.h>

bool DumpTargetGroup::InitAllTargets()
{
    std::unordered_set<SingleDumpTarget*> toRemove;

    for (auto& kv : mTargets)
    {
        if (kv.first->Init() == false)
            toRemove.insert(kv.first);
    }

    for (SingleDumpTarget* r : toRemove)
        RemoveTarget(r);

    return true;
}

bool DumpTargetGroup::Init()
{
    if (JSON_ASSERT(mDumpTargetDesc, "targets") == false)
        return false;

    if (JSON_ASSERT_STR_EMPTY(mDumpTargetDesc, "macro") == false)
    {
        printf("\"macro\" Not present or empty in \"%s\" Targets config\n", mTargetJsonPath.c_str());
        return false;
    }

    mMacro = mDumpTargetDesc.get<std::string>("macro", "");
    mResultJsonName = mDumpTargetDesc.get<std::string>("output_json_name", "offsets_" + mMacro + ".json");

    if (ReadAllTarget() == false)
        return false;

    if (InitAllTargets() == false)
        return false;

    return true;
}

void DumpTargetGroup::ComputeAll()
{
    ThreadPool tp;

    for (auto& kv : mTargets)
    {
        printf("Computing %s\n", kv.second->getCategoryName().c_str());

        tp.enqueue([&](SingleDumpTarget* pSingDumpTarg) {
            pSingDumpTarg->ComputeAll();
            }, kv.second.get());
    }
}

void DumpTargetGroup::ComputeJsonResult()
{
    for (auto& kv : mTargets)
        kv.second->ComputeJsonResult();
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

void DumpTargetGroup::setTargetJsonPath(const std::string& path)
{
    mTargetJsonPath = path;
}

bool DumpTargetGroup::ReadAllTarget()
{
    JsonValueWrapper targets = mDumpTargetDesc["targets"];

    if (targets.isArray() == false)
        return false;

    for (uint32_t i = 0; i < targets.size(); i++)
    {
        JsonValueWrapper curr(targets[i]);

        if (curr.isObject() != true)
            continue;

        std::unique_ptr<SingleDumpTarget> dumpTarget = std::make_unique<SingleDumpTarget>();

        dumpTarget->setDumpTargetDescJson(curr);
        dumpTarget->setTargetManager(mTargetMgr);
        ((SingleDumpTarget*)dumpTarget.get())->setParent(this);

        AddTarget(dumpTarget);
    }

    return true;
}

void DumpTargetGroup::WriteHppStaticDeclsDefs()
{
    if (mTargets.size() < 1)
        return;

    MacroBegin();

    for (auto& kv : mTargets)
        kv.first->WriteHppStaticDeclsDefs();

    MacroEnd();
}

void DumpTargetGroup::WriteHppDynDecls()
{
    if (mTargets.size() < 1)
        return;

    MacroBegin();

    for (auto& kv : mTargets)
        kv.first->WriteHppDynDecls();

    MacroEnd();
}

void DumpTargetGroup::WriteHppDynDefs()
{
    if (mTargets.size() < 1)
        return;

    MacroBegin();

    for (auto& kv : mTargets)
        kv.first->WriteHppDynDefs();

    MacroEnd();
}

void DumpTargetGroup::MacroBegin()
{
    mParent->getHppWriter()->AppendMacroIfDefined(mMacro);
}

void DumpTargetGroup::MacroEnd()
{
    mParent->getHppWriter()->AppendMacroEndIf();
}

HeaderFileManager* DumpTargetGroup::getHppWriter()
{
    return mParent->getHppWriter();
}

JsonValueWrapper* DumpTargetGroup::getResultJson()
{
    return &mResultJson;
}

bool DumpTargetGroup::SaveResultJsonToFile()
{
    if (mResultJsonName.empty())
        return false;

    return JsonHelper::Json2File(mResultJson, mResultJsonName);
}

std::string DumpTargetGroup::getMacro()
{
    return mMacro;
}
