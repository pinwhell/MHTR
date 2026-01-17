#include <format>
#include <iterator>
#include <algorithm>
#include <MHTR/Metadata/Synthers.h>
#include <MHTR/Synther/LineGroup.h>
#include <MHTR/Synther/NamespaceBlock.h>
#include <MHTR/Synther/Line.h>
#include <MHTR/Synther/MultiLineGroup.h>
#include <MHTR/Metadata/Utility.h>

using namespace MHTR;

MultiNsMultiMetadataSynther::MultiNsMultiMetadataSynther(const MetadataTargetSet& targets, const SynthCallback& callback, Indent indent)
    : mTargets(targets)
    , mCallback(callback)
    , mIndent(indent)
{}

std::vector<std::string> MultiNsMultiMetadataSynther::Synth() const
{
    std::vector<std::string> result;
    NamespaceMetadataTargetSetMap nsTargetsMap = NsMultiMetadataMapFromMultiMetadata(mTargets);
    int n = 0;

    for (const auto& kvNsTargets : nsTargetsMap)
    {
        std::vector<std::string> currNsRes = mCallback(kvNsTargets.first, kvNsTargets.second, mIndent);

        result.insert(result.end(), currNsRes.begin(), currNsRes.end());

        if (n++ < nsTargetsMap.size() - 1)
            result.push_back(""); // Empty line separating Namespaces
    }

    return result;
}

std::vector<std::string> ConstAssignSynther::Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent)
{
    std::vector<Line> allMetadata;

    std::transform(targets.begin(), targets.end(), std::back_inserter(allMetadata), [](MetadataTarget* target) {
        const auto& metadata = target->mResult.mMetadata;
        const std::string literalValue = ToLiteral(target);
        const std::string type = std::holds_alternative<PatternMetadata>(metadata) ? "auto" : "uint64_t";
        
        return Line(std::format("constexpr {} {} = {};", type, target->GetName(), literalValue));
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
    Line heading(std::format("{}:", ns));
    LineSynthesizerGroup headingLineGroup({ &heading });
    std::vector<Line> content;

    std::transform(targets.begin(), targets.end(), std::back_inserter(content), [](MetadataTarget* target) {
        return std::format(
            "{}: {}",
            target->GetName(),
            target->mHasResult
            ? ToLiteral(target)
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

MetadataProviderFunction::MetadataProviderFunction(const std::string& fnName, IMultiLineSynthesizer* fnContent, ILineSynthesizer* fnArgLn, std::string fnIndent)
    : mFunction(fnName, fnContent, fnArgLn, "MHTR::MetadataProvider", fnIndent)
{}

std::vector<std::string> MetadataProviderFunction::Synth() const
{
    return mFunction.Synth();
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
