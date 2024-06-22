#pragma once

#include <vector>
#include <string>
#include <MHTR/Metadata/Container.h>

namespace cxxopts {
	class Options;
	class ParseResult;
}

namespace MHTR {

	class IPlugin {
	public:
		virtual ~IPlugin() {}
		virtual std::string GetName() const = 0;
		virtual std::string GetDescription() const { return ""; }
		virtual void OnCLIRegister(cxxopts::Options& options) = 0;
		virtual void OnCLIParsed(cxxopts::ParseResult& parseRes) = 0;
		virtual void OnResult(const MetadataTargetSet& result) = 0;
	};

#define MHTRPLUGIN_METADATA(name, desc) \
std::string GetName() const { \
	return name; \
} \
\
std::string GetDescription() const { \
	return desc; \
}

}