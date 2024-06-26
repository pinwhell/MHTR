#pragma once

#include <memory>
#include <MHTR/Synther/INamespace.h>

namespace MHTR {
	class INamespaceFactory {
	public:
		virtual ~INamespaceFactory() {}
		virtual std::unique_ptr<INamespace> MakeNamespace() = 0;
	};
}