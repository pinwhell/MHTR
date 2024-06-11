#pragma once

#include <MHTR/Provider/IProvider.h>
#include <MHTR/Synther/INamespace.h>

class INamespaceProvider : public IProvider {
public:
	virtual ~INamespaceProvider() {}
	virtual INamespace* GetNamespace() = 0;
};