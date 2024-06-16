#pragma once

#include <unordered_set>
#include <vector>
#include <functional>
#include <string>
#include <MHTR/Metadata/Target.h>
#include <MHTR/Metadata/Utility.h>
#include <MHTR/Synther/Line.h>
#include <MHTR/Synther/LineGroup.h>
#include <MHTR/Synther/MultiLineGroup.h>
#include <MHTR/Synther/FunctionBlock.h>
#include <MHTR/Synther/Utility.h>

namespace MHTR {
    class MultiNsMultiMetadataSynther : public IMultiLineSynthesizer {
    public:
        using SynthCallback = std::function<std::vector<std::string>(const std::string&, const MetadataTargetSet&, Indent)>;

        MultiNsMultiMetadataSynther(const MetadataTargetSet& targets, const SynthCallback& callback, Indent indent = IndentMake());

        std::vector<std::string> Synth() const override;

        MetadataTargetSet mTargets;
        SynthCallback mCallback;
        Indent mIndent;
    };

    class ConstAssignSynther {
    public:
        static std::vector<std::string> Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent);
    };

    class TextReportSynther {
    public:
        static std::vector<std::string> Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent);
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

    class MetadataLiteralValueSynther {
    public:
        static std::string Synth(MetadataTarget* target)
        {
            return ToLiteral(target);
        }
    };

    class MetadataKeySynther {
    public:
        static std::string Synth(MetadataTarget* target)
        {
            return Literal(target->GetFullName());
        }
    };

    template<typename ValueSynther = MetadataLiteralValueSynther, typename KeySynther = MetadataKeySynther>
    class ProviderAssignFunctionSynther {
    public:
        static std::vector<std::string> Synth(const std::string& ns, const MetadataTargetSet& targets, const std::string& indent)
        {
            std::vector<Line> metadataLines;

            metadataLines.emplace_back("MHTR::MetadataMap result;");
            std::transform(targets.begin(), targets.end(), std::back_inserter(metadataLines), [](MetadataTarget* target) {

                return Line("result[" + KeySynther::Synth(target) + "] = " + ValueSynther::Synth(target) + ";");
                });

            metadataLines.emplace_back("return MHTR::MetadataProvider(std::move(result));");

            std::vector<ILineSynthesizer*> allFnLines; std::transform(metadataLines.begin(), metadataLines.end(), std::back_inserter(allFnLines), [](Line& line) {
                return &line;
                });

            LineSynthesizerGroup allFnLinesGroup(allFnLines);
            Line noArgs(Line::Empty());

            return MetadataProviderFunction(ns + "Create", &allFnLinesGroup, &noArgs, indent).Synth();
        }

        static std::vector<std::string> GetIncludes()
        {
            return {
                "cstdint",
                "MHTRSDK.h"
            };
        }
    };

    //template<typename Json, typename KeySynther = MetadataKeySynther>
    //class DefaultJsonValueSynther {
    //public:
    //    static std::string Synth(const std::string& jsonObjName, MetadataTarget* metadata)
    //    {
    //        std::string type = std::holds_alternative<PatternMetadata>(metadata->mResult.mMetadata) ? "std::string" : "uint64_t";
    //        return Json::AccessSynth(jsonObjName, KeySynther::Synth(metadata), type, false);
    //    }
    //};

   /* class FromJsonProviderAssignFunctionSynther : public IMultiLineSynthesizer {
    public:
        MultiLine Synth() const override
        {
            MultiLine metadataLines;

            metadataLines.emplace_back("MHTR::MetadataMap result;");
            std::transform(mTargets.begin(), mTargets.end(), std::back_inserter(metadataLines), [](MetadataTarget* target) {

                return Line("result[" + KeySynther::Synth(target) + "] = " + ValueSynther::Synth("json", target) + ";");
                });

            metadataLines.emplace_back("return MHTR::MetadataProvider(std::move(result));");

            std::vector<ILineSynthesizer*> allFnLines; std::transform(metadataLines.begin(), metadataLines.end(), std::back_inserter(allFnLines), [](Line& line) {
                return &line;
                });

            LineSynthesizerGroup allFnLinesGroup(allFnLines);
            Line args("const " + mJsonTypeSynther->Synth() + "& json");

            return MetadataProviderFunction(mNamespace + "Create", &allFnLinesGroup, &args, mIndent).Synth();
        }

        ILineSynthesizer* mJsonTypeSynther;
        std::string mNamespace;
        Indent mIndent;
    };*/

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