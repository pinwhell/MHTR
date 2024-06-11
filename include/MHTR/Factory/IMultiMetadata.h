#pragma once

#include <vector>
#include <memory>
#include <MHTR/ILookableMetadata.h>

namespace MHTR {
	class IMultiMetadataFactory {
	public:
		virtual ~IMultiMetadataFactory() {};
		virtual std::vector<std::unique_ptr<ILookableMetadata>> ProduceAll() = 0;
	};
}