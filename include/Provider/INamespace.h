#pragma once

#include <Provider/IProvider.h>
#include <Synther/INamespace.h>

class INamespaceProvider : public IProvider {
public:
	virtual ~INamespaceProvider() {}
	virtual INamespace* GetNamespace() = 0;
};