#include <Metadata.h>
#include <sstream>

template<>
std::string Metadata<uint64_t>::ToString() const {
	std::stringstream ss;
	ss << std::hex << "0x" << mValue;
	return ss.str();
}

template<>
std::string Metadata<std::string>::ToString() const {
	return mValue;
}

template<>
Metadata<uint64_t> Metadata<uint64_t>::operator+(const Metadata<uint64_t>& other) const {
	return Metadata<uint64_t>(mValue + other.mValue);
}

template<>
void Metadata<uint64_t>::operator+=(const Metadata<uint64_t>& other) {
	mValue += other.mValue;
}

MetadataResult::MetadataResult(uint64_t offset)
	: mType(EMetadataResult::OFFSET)
	, mOffset(offset)
{}

MetadataResult::MetadataResult(const std::string & pattern)
	: MetadataResult(pattern.c_str())
{}

MetadataResult::MetadataResult(const char* s)
	: mType(EMetadataResult::PATTERN)
	, mPattern(s)
{}

MetadataResult::~MetadataResult()
{}

std::string MetadataResult::ToString() const {
	switch (mType)
	{
	case EMetadataResult::PATTERN:
		return mPattern.ToString();
	case EMetadataResult::OFFSET:
		return mOffset.ToString();
	}

	return "";
}
