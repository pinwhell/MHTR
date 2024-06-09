#include <Metadata/Synthers.h>
#include <fmt/format.h>
#include <Synther/LineGroup.h>
#include <Synther/NamespaceBlock.h>
#include <iterator>
#include <Synther/Line.h>
#include <algorithm>
#include <Synther/MultiLineGroup.h>
#include <Metadata/Utility.h>

template<typename T>
inline std::string Literal(T str)
{
    return fmt::format("\"{}\"", str);
}

MetadataStaticLineSynther::MetadataStaticLineSynther(const MetadataTarget& target)
    : mTarget(target)
{}

std::string MetadataStaticLineSynther::Synth() const
{
    const auto& metadata = mTarget.mResult.mMetadata;
    
    if(std::holds_alternative<PatternMetadata>(metadata))
        return fmt::format("constexpr auto {} = {};", mTarget.GetName(), Literal(std::get<PatternMetadata>(metadata).mValue));

    if (std::holds_alternative<OffsetMetadata>(metadata))
        return fmt::format("constexpr uint64_t {} = 0x{:X};", mTarget.GetName(), std::get<OffsetMetadata>(metadata).mValue);

    throw std::logic_error("metadata line synthesizer not implemented");
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

MultiMetadataReportSynther::MultiMetadataReportSynther(std::vector<MetadataTarget*> targets, const std::string& ns)
    : mTargets(targets)
    , mNamespace(ns)
{}

std::vector<std::string> MultiMetadataReportSynther::Synth() const {
    std::vector<std::string> result{ fmt::format("{}:", mNamespace) };
    std::vector<Line> content;

    std::transform(mTargets.begin(), mTargets.end(), std::back_inserter(content), [](MetadataTarget* target) {
        const auto& result = target->mResult;
        bool bIsPattern = std::holds_alternative<PatternMetadata>(result.mMetadata);
        auto resultStr = target->mResult.ToString(); resultStr = bIsPattern ? Literal(resultStr) : resultStr;

        return fmt::format(
            "{}: {}",
            target->GetName(),
            target->mHasResult
            ? resultStr

            : "Not found."
        );
        });

    std::vector<ILineSynthesizer*> contentSynthers; std::transform(content.begin(), content.end(), std::back_inserter(contentSynthers), [](Line& line) {
        return &line;
        });

    LineSynthesizerGroup contentSynther(contentSynthers);
    ScopeBlock scopedContentSynther(&contentSynther);
    std::vector<std::string> scopedContent = scopedContentSynther.Synth();

    result.insert(result.end(), scopedContent.begin(), scopedContent.end());

    return result;
}

MultiNsMultiMetadataReportSynther::MultiNsMultiMetadataReportSynther(const std::vector<MetadataTarget*>& targets)
    : mTargets(targets)
{}

std::vector<std::string> MultiNsMultiMetadataReportSynther::Synth() const {
    std::vector<std::string> result;
    std::unordered_map<std::string, std::vector<MetadataTarget*>> nsTargetsMap = TargetsGetNamespacedMap(mTargets);

    int n = 0;

    for (const auto& kvNsTargets : nsTargetsMap)
    {
        std::vector<std::string> currNsRes = MultiMetadataReportSynther(kvNsTargets.second, kvNsTargets.first).Synth();

        result.insert(result.end(), currNsRes.begin(), currNsRes.end());

        if (n++ < nsTargetsMap.size() - 1)
            result.push_back(""); // Empty line separating Namespaces
    }

    return result;
}

HppStaticReport::HppStaticReport(const std::vector<MetadataTarget*>& targets)
    : mTargets(targets)
{}

std::vector<std::string> HppStaticReport::Synth() const
{
    Line pragmaOnce("#pragma once");
    Line emptyLine(Line::Empty());
    Line includeCstdint("#include <cstdint>");
    LineSynthesizerGroup headerGroup({
        &pragmaOnce,
        &emptyLine,
        &includeCstdint,
        &emptyLine
        });
    MultiNsMultiMetadataStaticSynther allNsSynther(mTargets);

    MultiLineSynthesizerGroup synthGroup({
        &headerGroup,
        &allNsSynther,
        });

    return synthGroup.Synth();
}

MetadataProviderFunction::MetadataProviderFunction(const std::string& fnName, IMultiLineSynthesizer* fnContent, ILineSynthesizer* fnArgLn, std::string fnIndent)
    : mFunction(fnName, fnContent, fnArgLn, "MHTR::MetadataProvider", fnIndent)
{}

std::vector<std::string> MetadataProviderFunction::Synth() const
{
    return mFunction.Synth();
}

MultiStaticAssignFunctionBody::MultiStaticAssignFunctionBody(std::vector<MetadataTarget*> results)
    : mResults(results)
{}

std::vector<std::string> MultiStaticAssignFunctionBody::Synth() const
{
    std::vector<Line> metadataLines;

    metadataLines.emplace_back("MHTR::MetadataMap result;");

    std::transform(mResults.begin(), mResults.end(), std::back_inserter(metadataLines), [](MetadataTarget* target) {
        bool bIsPattern = std::holds_alternative<PatternMetadata>(target->mResult.mMetadata);
        std::string fullValue = bIsPattern ? Literal(target->mResult.ToString()) : target->mResult.ToString() + "ull";
        return Line("result[" + Literal(target->GetFullName()) + "] = " + fullValue + ";");
        });

    metadataLines.emplace_back("return MHTR::MetadataProvider(std::move(result));");

    std::vector<ILineSynthesizer*> allFnLines;
    std::transform(metadataLines.begin(), metadataLines.end(), std::back_inserter(allFnLines), [](Line& line) {
        return &line;
        });
    return LineSynthesizerGroup(allFnLines).Synth();
}

MetadataStaticAssignFunction::MetadataStaticAssignFunction(const std::vector<MetadataTarget*>& results, const std::string& ns, std::string indent)
    : mResults(results)
    , mNamespace(ns)
    , mIndent(indent)
{}

std::vector<std::string> MetadataStaticAssignFunction::Synth() const
{
    MultiStaticAssignFunctionBody fnContent(mResults);
    Line noArgs(Line::Empty());
    return MetadataProviderFunction(mNamespace + "Create", &fnContent, &noArgs, mIndent).Synth();
}

MultiNsMultiMetadataStaticAssignFunction::MultiNsMultiMetadataStaticAssignFunction(const std::vector<MetadataTarget*>& results, std::string indent)
    : mResults(results)
    , mIndent(indent)
{}

std::vector<std::string> MultiNsMultiMetadataStaticAssignFunction::Synth() const
{
    std::vector<std::string> result;
    std::unordered_map<std::string, std::vector<MetadataTarget*>> nsTargetsMap = TargetsGetNamespacedMap(mResults);

    int n = 0;

    for (const auto& kvNsTargets : nsTargetsMap)
    {
        std::vector<std::string> currNsRes = MetadataStaticAssignFunction(kvNsTargets.second, kvNsTargets.first, mIndent).Synth();

        result.insert(result.end(), currNsRes.begin(), currNsRes.end());

        if (n++ < nsTargetsMap.size() - 1)
            result.push_back(""); // Empty line separating Namespaces
    }

    return result;
}

