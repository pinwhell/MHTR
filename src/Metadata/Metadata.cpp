#include <Metadata/Metadata.h>
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