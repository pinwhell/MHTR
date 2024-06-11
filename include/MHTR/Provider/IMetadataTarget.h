#pragma once

#include <string>
#include <MHTR/Synther/INamespace.h>
#include <MHTR/Metadata/Target.h>

class IMetadataTargetProvider {
public:
    virtual MetadataTarget* GetMetadataTarget(const std::string& name, INamespace* ns = nullptr) = 0;
    virtual ~IMetadataTargetProvider() {}
};