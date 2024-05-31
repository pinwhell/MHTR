#pragma once

#include <Synther/INamespace.h>

class INamespaceProvider {
public:
	virtual ~INamespaceProvider() {}
	virtual INamespace* GetNamespace() = 0;
};