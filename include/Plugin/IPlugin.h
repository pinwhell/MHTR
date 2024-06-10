#pragma once

#include <vector>
#include <string>
#include <Api.h>
#include <Metadata/Container.h>

class IPlugin {
public:
	virtual ~IPlugin() {}
	virtual std::string GetName() const = 0;
	virtual std::string GetDescription() const { return ""; }
	virtual void Init(int argc = 0, const char* argv[] = nullptr) = 0;
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

#define MHTRPLUGIN_EXPORT(x) \
MHTR_EXPORT IPlugin* CreatePlugin() \
{ \
	return new x(); \
}

using CreatePluginFn = IPlugin*(*)();