#include <iostream>
#include <MHTR/Plugin/IPlugin.h>
#include <MHTR/Plugin/Export.h>

using namespace MHTR;

class SampleReportPlugin : public IPlugin {
public:
	MHTRPLUGIN_METADATA("Sample Report Plugin", "")

	void OnCLIRegister(cxxopts::Options& options) override
	{}

	void OnCLIParsed(cxxopts::ParseResult& parseRes) override
	{}

	void OnResult(const MetadataTargetSet& result) override
	{
		if (result.empty())
			return;

		std::cout << "SampleReportPlugin Processing " << result.size() << " Results ...\n";
	}	
};

MHTRPLUGIN_EXPORT(SampleReportPlugin)