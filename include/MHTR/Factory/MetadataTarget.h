#pragma once

#include <MHTR/Provider/IMetadataTarget.h>

#include <unordered_map>
#include <string>
#include <memory>

// Flygweight Metadata Target Factory Owninig & Providing
// Centralized access to Metadata Targets

class MetadataTargetFactory : public IMetadataTargetProvider {
public:
    // a map perfectly mapping the fully qualified name 
    // from the metadata target to its metadata target object

    MetadataTarget* GetMetadataTarget(const std::string& name, INamespace* ns = nullptr) override;

    std::unordered_map<std::string, std::unique_ptr<MetadataTarget>> mMetadataTargetMap;
};