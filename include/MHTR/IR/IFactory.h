#pragma once

#include <vector>
#include <MHTR/IR/Metadata.h>

class IMultiMetadataIRFactory {
public:
    virtual std::vector<MetadataIR> GetAllMetadatas() = 0;
	virtual ~IMultiMetadataIRFactory() {}
};