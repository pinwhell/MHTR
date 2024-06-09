#include <Plugin/IPlugin.h>
#include <cxxopts.hpp>
#include <Synther/Line.h>
#include <Synther/NamespaceBlock.h>
#include <Synther/LineGroup.h>
#include <Synther/FileOperations.h>
#include <Synther/MultiLineGroup.h>
#include <Metadata/Synthers.h>
#include <Metadata/Utility.h>

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

		std::unordered_map<std::string, std::vector<MetadataTarget*>> namespacedMap = TargetsGetNamespacedMap(result);
		std::vector<std::string> listNamespaces;

		std::transform(namespacedMap.begin(), namespacedMap.end(), std::back_inserter(listNamespaces), [](const auto& kv) {
			return kv.first;
			});

		std::sort(listNamespaces.begin(), listNamespaces.end());

		std::string reportNsName = "";

		for (const std::string& ns : listNamespaces)
			reportNsName += ns;

		MultiNsMultiMetadataStaticAssignFunction multiFn(result);
		Line pragmaOnce("#pragma once");
		Line includeSdk("#include <MHTRSDK.h>");
		Line empty = Line::Empty();
		LineSynthesizerGroup hppHeader({
			&pragmaOnce,
			&empty,
			&includeSdk,
			&empty
			});
		NamespaceBlock nsBlock(&multiFn, reportNsName);
		MultiLineSynthesizerGroup fullHpp({
			&hppHeader,
			&nsBlock
			});
		FileWrite(mCLIParseRes["report-hpprt"].as<std::string>(), &fullHpp);
	}

	cxxopts::Options mCLIOptions;
	cxxopts::ParseResult mCLIParseRes;
};

MHTRPLUGIN_EXPORT(HPPRTReportWriter)