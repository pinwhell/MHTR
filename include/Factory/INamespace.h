#pragma once

#include <memory>
#include <Synther/INamespace.h>

class INamespaceFactory {
public:
	virtual ~INamespaceFactory() {}
	virtual std::unique_ptr<INamespace> MakeNamespace() = 0;
};