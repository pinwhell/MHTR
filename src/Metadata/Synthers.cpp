#include <fmt/format.h>
#include <iterator>
#include <algorithm>
#include <MHTR/Metadata/Synthers.h>
#include <MHTR/Synther/LineGroup.h>
#include <MHTR/Synther/NamespaceBlock.h>
#include <MHTR/Synther/Line.h>
#include <MHTR/Synther/MultiLineGroup.h>
#include <MHTR/Metadata/Utility.h>

using namespace MHTR;

template<typename T>
inline std::string Literal(T str)
{
    return fmt::format("\"{}\"", str);
}

std::vector<std::string> ConstAssignSynther::Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent)
{
    std::vector<Line> allMetadata;

    std::transform(targets.begin(), targets.end(), std::back_inserter(allMetadata), [](MetadataTarget* target) {
        const auto& metadata = target->mResult.mMetadata;

        if (std::holds_alternative<PatternMetadata>(metadata))
            return Line(fmt::format("constexpr auto {} = {};", target->GetName(), Literal(std::get<PatternMetadata>(metadata).mValue)));

        if (std::holds_alternative<OffsetMetadata>(metadata))
            return Line(fmt::format("constexpr uint64_t {} = 0x{:X};", target->GetName(), std::get<OffsetMetadata>(metadata).mValue));

        throw std::logic_error("metadata line synthesizer not implemented");
        });

    std::vector<ILineSynthesizer*> allMetadataSynthers; std::transform(allMetadata.begin(), allMetadata.end(), std::back_inserter(allMetadataSynthers), [](Line& line) {
        return &line;
        });

    LineSynthesizerGroup allMetadataGroup(allMetadataSynthers);

    if (ns == METADATA_NS_NULL)
        return allMetadataGroup.Synth();

    return NamespaceBlock(&allMetadataGroup, ns, indent).Synth();
}

std::vector<std::string> TextReportSynther::Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent)
{
    Line heading(fmt::format("{}:", ns));
    LineSynthesizerGroup headingLineGroup({ &heading });
    std::vector<Line> content;

    std::transform(targets.begin(), targets.end(), std::back_inserter(content), [](MetadataTarget* target) {
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
    ScopeBlock scopedContentSynther(&contentSynther, indent);

    return MultiLineSynthesizerGroup({
        &headingLineGroup,
        &scopedContentSynther
        }).Synth();
}

HppConstAssignSynther::HppConstAssignSynther(const MetadataTargetSet& targets)
    : mTargets(targets)
{}

std::vector<std::string> HppConstAssignSynther::Synth() const
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
    MultiNsMultiMetadataSynther<ConstAssignSynther> allNsSynther(mTargets);
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

std::vector<std::string> ProviderAssignFunctionSynther::Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent)
{
    std::vector<Line> metadataLines;

    metadataLines.emplace_back("MHTR::MetadataMap result;");
    std::transform(targets.begin(), targets.end(), std::back_inserter(metadataLines), [](MetadataTarget* target) {
        bool bIsPattern = std::holds_alternative<PatternMetadata>(target->mResult.mMetadata);
        std::string fullValue = bIsPattern ? Literal(target->mResult.ToString()) : target->mResult.ToString() + "ull";
        return Line("result[" + Literal(target->GetFullName()) + "] = " + fullValue + ";");
        });

    metadataLines.emplace_back("return MHTR::MetadataProvider(std::move(result));");

    std::vector<ILineSynthesizer*> allFnLines; std::transform(metadataLines.begin(), metadataLines.end(), std::back_inserter(allFnLines), [](Line& line) {
        return &line;
        });

    LineSynthesizerGroup allFnLinesGroup(allFnLines);
    Line noArgs(Line::Empty());

    return MetadataProviderFunction(ns + "Create", &allFnLinesGroup, &noArgs, indent).Synth();
}

MetadataProviderMergerFunctionBody::MetadataProviderMergerFunctionBody(const NamespaceSet& allNs)
    : mAllNs(allNs)
{}

std::vector<std::string> MetadataProviderMergerFunctionBody::Synth() const
{
    Line allProvider("MHTR::MetadataProvider all;");
    std::set<std::string> allProviderFnName = FromNsAllFnNames();
    std::vector<Line> allEveryOtherAddition;
    std::transform(allProviderFnName.begin(), allProviderFnName.end(), std::back_inserter(allEveryOtherAddition), [](const std::string& providerFnName) {
        return Line("all += " + providerFnName + "();");
        });
    Line returnStatement("return  all;");
    std::vector<ILineSynthesizer*> allHppLines = {
        &allProvider
    };
    std::transform(allEveryOtherAddition.begin(), allEveryOtherAddition.end(), std::back_inserter(allHppLines), [](Line& ln) {
        return &ln;
        });
    allHppLines.push_back(&returnStatement);
    return LineSynthesizerGroup(allHppLines).Synth();
}

std::set<std::string> MetadataProviderMergerFunctionBody::FromNsAllFnNames() const
{
    std::set<std::string> result;

    std::transform(mAllNs.begin(), mAllNs.end(), std::inserter(result, result.end()), [](const std::string& ns) {
        return ns + "Create";
        });

    return result;
}

MetadataProviderMergerFunction::MetadataProviderMergerFunction(const NamespaceSet& allNs, std::string fnIndent)
    : mEmptyLine(Line::Empty())
    , mBody(allNs)
    , mFunction("AllCreate", &mBody, &mEmptyLine, fnIndent)
{}

MetadataProviderMergerFunction::MetadataProviderMergerFunction(const MetadataTargetSet& allResult, std::string fnIndent)
    : MetadataProviderMergerFunction(AllNsFromMultiMetadataTarget(allResult), fnIndent)
{}

std::vector<std::string> MetadataProviderMergerFunction::Synth() const
{
    return mFunction.Synth();
}
