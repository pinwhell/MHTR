#pragma once

#include <memory>
#include "IOffset.h"
#include "JsonValueWrapper.h"

class OffsetClassifier
{
public:
	static void Classify(JsonValueWrapper& metadata, std::unique_ptr<IOffset>& outOffset);
};

