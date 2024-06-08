#include <Plugin/IPlugin.h>

class SampleReportPlugin : public IPlugin {
public:
	MHTRPLUGIN_METADATA("Sample Report Plugin", "")

	void Init(int argc = 0, const char* argv[] = nullptr) override
	{

	}

	void OnResult(const std::vector<MetadataTarget*>& result) override
	{

	}
};

MHTRPLUGIN_EXPORT(SampleReportPlugin)