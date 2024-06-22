#include <MHTR/Plugin/Registration.h>

using namespace MHTR;

std::vector<PluginInstancer> PluginRegistration::mMultiInstancer;

void MHTR::PluginRegistration::InstancerRegister(PluginInstancer instancer)
{
	mMultiInstancer.emplace_back(std::move(instancer));
}

std::vector<std::unique_ptr<IPlugin>> MHTR::PluginRegistration::InstanceAll()
{
	std::vector<std::unique_ptr<IPlugin>> allPlugins;

	for (const auto& instancer : mMultiInstancer)
		allPlugins.emplace_back(std::move(instancer()));

	return allPlugins;
}
