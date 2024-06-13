#include <cxxopts.hpp>
#include <MHTR/Plugin/IPlugin.h>
#include <MHTR/Synther/Line.h>
#include <MHTR/Synther/LineGroup.h>
#include <MHTR/Synther/MultiLineGroup.h>
#include <MHTR/Synther/NamespaceBlock.h>
#include <MHTR/Synther/FileOperations.h>
#include <MHTR/Metadata/Utility.h>
#include <MHTR/Metadata/Synthers.h>

using namespace MHTR;

class HPPRTReportWriter : public IPlugin {
public:
	MHTRPLUGIN_METADATA("HPPRT Report Writer Plugin", "Creates a Runtime Hpp Report using MHTRSDK")

	void OnCLIRegister(cxxopts::Options& options) override
	{
		mOptions = &options;
		options.add_options()
			("rhpprt,report-hpprt", "Generates HPP Runtime Report using MHTRSDK", cxxopts::value<std::string>());
	}

	void OnCLIParsed(cxxopts::ParseResult& parseRes) override
	{
		mbWant = parseRes.count("report-hpprt") != 0;

		if (!mbWant)
			return;

		mReportOutputPath = parseRes["report-hpprt"].as<std::string>();
	}

	void OnResult(const MetadataTargetSet& result) override
	{
		if (!mbWant || result.empty())
			return;

		// At this point there is result available & user requested a
		// report from the plugin

		NamespaceMetadataTargetSetMap namespacedMap = NsMultiMetadataMapFromMultiMetadata(result);
		NamespaceSet allNs = AllNsFromMultiMetadataTarget(result);

		std::string reportNsName = ""; for (const std::string& ns : allNs)
			reportNsName += ns;

		Line empty = Line::Empty();
		LineSynthesizerGroup newLineMultiLineSynther({ &empty });
		Line pragmaOnce("#pragma once");
		Line includeSdk("#include <MHTRSDK.h>");
		LineSynthesizerGroup hppHeader({
			&pragmaOnce,
			&empty,
			&includeSdk,
			&empty
			});
		MultiNsMultiMetadataSynther<ProviderAssignFunctionSynther> multiFn(result);
		MetadataProviderMergerFunction multiProviderMerger(result);
		MultiLineSynthesizerGroup multiFnAndMerger({
			&multiFn,
			&newLineMultiLineSynther,
			&multiProviderMerger
			});
		NamespaceBlock fullNsBlock(&multiFnAndMerger, reportNsName);
		MultiLineSynthesizerGroup fullHpp({
			&hppHeader,
			&fullNsBlock
			});
		FileWrite(mReportOutputPath, &fullHpp);
	}

	bool mbWant = false;
	std::string mReportOutputPath;
	cxxopts::Options* mOptions;
};

MHTRPLUGIN_EXPORT(HPPRTReportWriter)
