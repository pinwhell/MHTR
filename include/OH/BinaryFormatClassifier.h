#pragma once

#include <string>
#include "IBinaryFormat.h"
#include <string>

class BinaryFormatClassifier
{
public:
	static bool Classify(unsigned char* bin, std::unique_ptr<IBinaryFormat>& outBinFormat, bool bSetBinAsBase = true);
	static bool Classify(std::string& binFormat, std::unique_ptr<IBinaryFormat>& outBinFormat, unsigned char* bin = nullptr);
};

