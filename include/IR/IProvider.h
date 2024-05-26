#pragma once

#include <vector>
#include <IR/Metadata.h>

class IMultiMetadataIRProvider {
public:
    virtual std::vector<MetadataIR> GetAllMetadatas() = 0;
	virtual ~IMultiMetadataIRProvider() {}
};