#include <Plugin/IPlugin.h>
#include <cxxopts.hpp>
#include <Synther/Line.h>
#include <Synther/LineGroup.h>
#include <Synther/MultiLineGroup.h>
#include <Synther/NamespaceBlock.h>
#include <Synther/FileOperations.h>
#include <Metadata/Utility.h>
#include <Metadata/Synthers.h>

class HPPRTReportWriter : public IPlugin {
public:
	HPPRTReportWriter()
		: mCLIOptions(GetName())
	{
		mCLIOptions.allow_unrecognised_options();
	}

	MHTRPLUGIN_METADATA("HPPRT Report Writer Plugin", "Creates a Runtime Hpp Report using MHTRSDK")

	void Init(int argc, const char* argv[]) override
	{
		mCLIOptions.add_options()
			("rhpprt,report-hpprt", "Generates HPP Runtime Report using MHTRSDK", cxxopts::value<std::string>());

		mCLIOptions.allow_unrecognised_options();

		mCLIParseRes = mCLIOptions.parse(argc, argv);
	}

	void OnResult(const std::vector<MetadataTarget*>& result) override
	{
		if (result.empty() || !mCLIParseRes.count("report-hpprt"))
			return;

		// At this point there is result available & user requested a
		// report from the plugin

		std::unordered_map<std::string, std::vector<MetadataTarget*>> namespacedMap = NsMultiMetadataMapFromMultiMetadata(result);
		std::vector<std::string> listNamespaces;

		std::transform(namespacedMap.begin(), namespacedMap.end(), std::back_inserter(listNamespaces), [](const auto& kv) {
			return kv.first;
			});

		std::sort(listNamespaces.begin(), listNamespaces.end());

		std::string reportNsName = "";

		for (const std::string& ns : listNamespaces)
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
		MultiNsMultiMetadataStaticAssignFunction multiFn(result);
		MultiMetadataProviderMergerFunction multiProviderMerger(result);
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
		FileWrite(mCLIParseRes["report-hpprt"].as<std::string>(), &fullHpp);
	}

	cxxopts::Options mCLIOptions;
	cxxopts::ParseResult mCLIParseRes;
};

MHTRPLUGIN_EXPORT(HPPRTReportWriter)
