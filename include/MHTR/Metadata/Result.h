#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <MHTR/Metadata/Metadata.h>
#include <MHTR/Metadata/EMetadata.h>

namespace MHTR {

	struct MetadataResult {
		MetadataResult(uint64_t offset);
		MetadataResult(const std::string& pattern);

		std::string ToString() const;
		EMetadataResult getType() const;

		std::variant<OffsetMetadata, PatternMetadata> mMetadata;
	};

}