#pragma once

#include <MHTR/Api.h>
#include <MHTR/Plugin/IPlugin.h>

namespace MHTR {
	using CreatePluginFn = IPlugin * (*)();

#define MHTRPLUGIN_EXPORT(x) \
MHTR_EXPORT IPlugin* CreatePlugin() \
{ \
	return new x(); \
}

}