#include <Plugin/IPlugin.h>
#include <iostream>

class SampleReportPlugin : public IPlugin {
public:
	MHTRPLUGIN_METADATA("Sample Report Plugin", "")

	void Init(int argc = 0, const char* argv[] = nullptr) override
	{
		if (!argc)
			return;

		std::cout << "SampleReportPlugin Initialized with " << argc << " Command Line Arguments...\n";
	}

	void OnResult(const MetadataTargetSet& result) override
	{
		if (result.empty())
			return;

		std::cout << "SampleReportPlugin Processing " << result.size() << " Results ...\n";
	}
};

MHTRPLUGIN_EXPORT(SampleReportPlugin)