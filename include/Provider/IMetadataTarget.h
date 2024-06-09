#pragma once

#include <Metadata/Target.h>
#include <string>
#include <Synther/INamespace.h>

class IMetadataTargetProvider {
public:
    virtual MetadataTarget* GetMetadataTarget(const std::string& name, INamespace* ns = nullptr) = 0;
    virtual ~IMetadataTargetProvider() {}
};