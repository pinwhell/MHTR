#pragma once

#include <unordered_set>
#include <Metadata/Target.h>
#include <Synther/ILine.h>
#include <Synther/IMultiLine.h>
#include <Synther/FunctionBlock.h>
#include <Synther/Line.h>

class MetadataStaticLineSynther : public ILineSynthesizer {
public:
    MetadataStaticLineSynther(const MetadataTarget& target);

    std::string Synth() const override;

    const MetadataTarget& mTarget;
};

class MultiMetadataStaticSynther : public IMultiLineSynthesizer
{
public:
    MultiMetadataStaticSynther(std::vector<MetadataTarget*> targets, const std::string& ns = METADATA_NS_NULL);

    std::vector<std::string> Synth() const override;

    std::string mNamespace;
    std::vector<MetadataTarget*> mTargets;
};

class MultiNsMultiMetadataStaticSynther : public IMultiLineSynthesizer {
public:

    MultiNsMultiMetadataStaticSynther(const std::vector<MetadataTarget*>& targets);

    std::vector<std::string> Synth() const override;

    std::vector<MetadataTarget*> mTargets;
};

class MultiMetadataReportSynther : public IMultiLineSynthesizer
{
public:
    MultiMetadataReportSynther(std::vector<MetadataTarget*> targets, const std::string& ns = METADATA_NS_NULL);

    std::vector<std::string> Synth() const override;

    std::string mNamespace;
    std::vector<MetadataTarget*> mTargets;
};

class MultiNsMultiMetadataReportSynther : public IMultiLineSynthesizer {
public:
    MultiNsMultiMetadataReportSynther(const std::vector<MetadataTarget*>& targets);

    std::vector<std::string> Synth() const override;

    std::vector<MetadataTarget*> mTargets;
};

class HppStaticReport : public IMultiLineSynthesizer {
public:
    HppStaticReport(const std::vector<MetadataTarget*>& targets);

    std::vector<std::string> Synth() const override;

    std::vector<MetadataTarget*> mTargets;
};

class MetadataProviderFunction : public IMultiLineSynthesizer {
public:
    MetadataProviderFunction(
        const std::string& fnName,
        IMultiLineSynthesizer* fnContent,
        ILineSynthesizer* fnArgLn,
        std::string fnIndent = IndentMake());


    std::vector<std::string> Synth() const override;

    FunctionBlock mFunction;
};

class MultiStaticAssignFunctionBody : public IMultiLineSynthesizer {
public:
    MultiStaticAssignFunctionBody(std::vector<MetadataTarget*> results);

    std::vector<std::string> Synth() const override;

    std::vector<MetadataTarget*> mResults;
};

class MetadataStaticAssignFunction : public IMultiLineSynthesizer {
public:
    MetadataStaticAssignFunction(const std::vector<MetadataTarget*>& results, const std::string& ns, std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    std::string mNamespace;
    std::vector<MetadataTarget*> mResults;
    std::string mIndent;
};

class MultiNsMultiMetadataStaticAssignFunction : public IMultiLineSynthesizer {
public:

    MultiNsMultiMetadataStaticAssignFunction(const std::vector<MetadataTarget*>& results, std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    std::vector<MetadataTarget*> mResults;
    std::string mIndent;
};

class MultiMetadataProviderMergerFunctionBody : public IMultiLineSynthesizer {
public:
    MultiMetadataProviderMergerFunctionBody(const std::unordered_set<std::string>& allNs);

    std::vector<std::string> Synth() const override;

    std::unordered_set<std::string> mAllNs;

private:

    std::unordered_set<std::string> FromNsAllFnNames() const;
};

class MultiMetadataProviderMergerFunction : public IMultiLineSynthesizer {
public:
    MultiMetadataProviderMergerFunction(const std::unordered_set<std::string>& allNs, std::string fnIndent = IndentMake());
    MultiMetadataProviderMergerFunction(const std::vector<MetadataTarget*>& allResult, std::string fnIndent = IndentMake());

    std::vector<std::string> Synth() const override;
private:
    Line mEmptyLine;

public:
    MultiMetadataProviderMergerFunctionBody mBody;
    MetadataProviderFunction mFunction;
};