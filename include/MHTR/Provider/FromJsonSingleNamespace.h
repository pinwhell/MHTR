#pragma once

#include <MHTR/Provider/IJson.h>
#include <MHTR/Provider/INamespace.h>
#include <MHTR/Synther/Namespace.h>

namespace MHTR {

    class FromJsonSingleNamespaceProvider : public INamespaceProvider {
    public:
        FromJsonSingleNamespaceProvider(IJsonProvider* jsonProvider);

        INamespace* GetNamespace() override;

        Namespace mNs;
    };

}
