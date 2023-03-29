#pragma once

#include "IOffsetScanAlgo.h"
#include "JsonValueWrapper.h"
#include <memory>

class ScanAlgoClassifier
{
public:
	static bool Classify(const JsonValueWrapper& mtdInfo, std::unique_ptr<IOffsetScanAlgo>& outScanAlgo);
};

