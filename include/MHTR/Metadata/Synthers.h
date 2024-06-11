#pragma once

#include <unordered_set>
#include <MHTR/Metadata/Target.h>
#include <MHTR/Metadata/Utility.h>
#include <MHTR/Synther/ILine.h>
#include <MHTR/Synther/IMultiLine.h>
#include <MHTR/Synther/FunctionBlock.h>
#include <MHTR/Synther/Line.h>

namespace MHTR {

    template<typename T>
    class MultiNsMultiMetadataSynther : public IMultiLineSynthesizer {
    public:
        using SyntherT = T;

        inline MultiNsMultiMetadataSynther(const MetadataTargetSet& targets, std::string indent = IndentMake())
            : mTargets(targets)
            , mIndent(indent)
        {}

        inline std::vector<std::string> Synth() const override
        {
            std::vector<std::string> result;
            NamespaceMetadataTargetSetMap nsTargetsMap = NsMultiMetadataMapFromMultiMetadata(mTargets);
            int n = 0;

            for (const auto& kvNsTargets : nsTargetsMap)
            {
                std::vector<std::string> currNsRes = SyntherT::Synth(kvNsTargets.first, kvNsTargets.second, mIndent);

                result.insert(result.end(), currNsRes.begin(), currNsRes.end());

                if (n++ < nsTargetsMap.size() - 1)
                    result.push_back(""); // Empty line separating Namespaces
            }

            return result;
        }

        MetadataTargetSet mTargets;
        std::string mIndent;
    };

    class ConstAssignSynther {
    public:
        static std::vector<std::string> Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent);
    };

    class TextReportSynther {
    public:
        static std::vector<std::string> Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent);
    };

    class ProviderAssignFunctionSynther {
    public:
        static std::vector<std::string> Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent);
    };

    class HppConstAssignSynther : public IMultiLineSynthesizer {
    public:
        HppConstAssignSynther(const MetadataTargetSet& targets);

        std::vector<std::string> Synth() const override;

        MetadataTargetSet mTargets;
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

    class MetadataProviderMergerFunctionBody : public IMultiLineSynthesizer {
    public:
        MetadataProviderMergerFunctionBody(const NamespaceSet& allNs);

        std::vector<std::string> Synth() const override;

        NamespaceSet mAllNs;

    private:

        std::set<std::string> FromNsAllFnNames() const;
    };

    class MetadataProviderMergerFunction : public IMultiLineSynthesizer {
    public:
        MetadataProviderMergerFunction(const NamespaceSet& allNs, std::string fnIndent = IndentMake());
        MetadataProviderMergerFunction(const MetadataTargetSet& allResult, std::string fnIndent = IndentMake());

        std::vector<std::string> Synth() const override;
    private:
        Line mEmptyLine;

    public:
        MetadataProviderMergerFunctionBody mBody;
        MetadataProviderFunction mFunction;
    };

}