#pragma once

#include <vector>
#include <MHTR/IR/Metadata.h>

namespace MHTR {
	class IMultiMetadataIRFactory {
	public:
		virtual std::vector<MetadataIR> GetAllMetadatas() = 0;
		virtual ~IMultiMetadataIRFactory() {}
	};
}