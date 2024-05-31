#pragma once

#include <vector>
#include <memory>
#include <Metadata.h>

class IMultiMetadataFactory {
public:
	virtual ~IMultiMetadataFactory() {};
	virtual std::vector<std::unique_ptr<ILookableMetadata>> ProduceAll() = 0;
};