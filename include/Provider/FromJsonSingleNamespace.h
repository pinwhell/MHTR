#pragma once

#include <Provider/IJson.h>
#include <Provider/INamespace.h>
#include <Synther/Namespace.h>

class FromJsonSingleNamespaceProvider : public INamespaceProvider {
public:
    FromJsonSingleNamespaceProvider(IJsonProvider* jsonProvider);

    INamespace* GetNamespace() override;

    Namespace mNs;
};
