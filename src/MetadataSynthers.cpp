#include <MetadataSynthers.h>
#include <fmt/format.h>
#include <Synther/LineGroup.h>
#include <Synther/NamespaceBlock.h>

template<typename T>
std::string Literal(T str)
{
    return fmt::format("\"{}\"", str);
}

MetadataStaticLineSynther::MetadataStaticLineSynther(const MetadataTarget& target)
    : mTarget(target)
{}

std::string MetadataStaticLineSynther::Synth() const
{
    const auto& res = mTarget.mResult;

    switch (res.mType)
    {
    case EMetadataResult::PATTERN:
        return fmt::format("constexpr auto {} = {};", mTarget.GetName(), Literal(res.mPattern.mValue));

    case EMetadataResult::OFFSET:
        return fmt::format("constexpr uint64_t {} = 0x{:X};", mTarget.GetName(), res.mOffset.mValue);

    default:
        throw std::logic_error("metadata line synthesizer not implemented");
    }
}

MultiMetadataStaticSynther::MultiMetadataStaticSynther(std::vector<MetadataTarget*> targets, const std::string& ns)
    : mTargets(targets)
    , mNamespace(ns)
{}

std::vector<std::string> MultiMetadataStaticSynther::Synth() const
{
    std::vector<MetadataStaticLineSynther> targetSynthers;
    std::vector<ILineSynthesizer*> targetIfaceSynthers;

    targetSynthers.reserve(mTargets.size());    // to guratnee no re-allocation
    // so we can sucessfully push back
    // into targetIfaceSynthers without
    // addresses getting invalidated

    for (auto* target : mTargets)
    {
        targetSynthers.emplace_back(MetadataStaticLineSynther(*target));
        targetIfaceSynthers.push_back(&targetSynthers.back());
    }

    LineSynthesizerGroup constObjLines(targetIfaceSynthers);

    if (mNamespace != METADATA_NULL_NS)
        return NamespaceBlock(&constObjLines, mNamespace).Synth();

    return constObjLines.Synth();
}

MultiNsMultiMetadataStaticSynther::MultiNsMultiMetadataStaticSynther(const std::vector<MetadataTarget*>& targets)
    : mTargets(targets)
{}

std::vector<std::string> MultiNsMultiMetadataStaticSynther::Synth() const
{
    std::vector<std::string> result;
    std::unordered_map<std::string, std::vector<MetadataTarget*>> nsTargetsMap = TargetsGetNamespacedMap(mTargets);
    int n = 0;

    for (const auto& kvNsTargets : nsTargetsMap)
    {
        std::vector<std::string> currNsRes = MultiMetadataStaticSynther(kvNsTargets.second, kvNsTargets.first).Synth();

        result.insert(result.end(), currNsRes.begin(), currNsRes.end());

        if (n++ < nsTargetsMap.size() - 1)
            result.push_back(""); // Empty line separating Namespaces
    }

    return result;
}
