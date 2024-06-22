#pragma once

#include <functional>
#include <memory>
#include <vector>

#include <MHTR/Singleton.h>
#include <MHTR/Plugin/IPlugin.h>

namespace MHTR {
	using PluginInstancer = std::function<std::unique_ptr<IPlugin>()>;
	class PluginRegistration {
	public:
		static void InstancerRegister(PluginInstancer instancer);
		static std::vector<std::unique_ptr<IPlugin>> InstanceAll();

	private:
		static std::vector<PluginInstancer> mMultiInstancer;
	};

#define MHTRPLUGIN_REGISTER(x) \
auto annon##x = []{ \
	PluginRegistration::InstancerRegister([]{ \
		return std::make_unique< x >(); \
		}); \
	return 0; \
	}();
}