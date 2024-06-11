#include <MHTR/Metadata/Result.h>

MetadataResult::MetadataResult(uint64_t offset)
	: mMetadata(offset)
{}

MetadataResult::MetadataResult(const std::string& pattern)
	: mMetadata(pattern)
{}

std::string MetadataResult::ToString() const {
	if (std::holds_alternative<OffsetMetadata>(mMetadata))
		return std::get<OffsetMetadata>(mMetadata).ToString();

	if (std::holds_alternative<PatternMetadata>(mMetadata))
		return std::get<PatternMetadata>(mMetadata).ToString();

	return "";
}

EMetadataResult MetadataResult::getType() const
{
	return (EMetadataResult)mMetadata.index();
}