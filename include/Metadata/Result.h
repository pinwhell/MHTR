#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <Metadata/Metadata.h>
#include <Metadata/EMetadata.h>

struct MetadataResult {
	MetadataResult(uint64_t offset);
	MetadataResult(const std::string& pattern);

	std::string ToString() const;
	EMetadataResult getType() const;

	std::variant<OffsetMetadata, PatternMetadata> mMetadata;
};