#pragma once

#include <vector>
#include <memory>
#include <ILookableMetadata.h>

class IMultiMetadataFactory {
public:
	virtual ~IMultiMetadataFactory() {};
	virtual std::vector<std::unique_ptr<ILookableMetadata>> ProduceAll() = 0;
};