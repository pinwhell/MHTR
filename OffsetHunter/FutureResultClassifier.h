#pragma once

#include <memory>
#include "IFutureResult.h"
#include "JsonValueWrapper.h"

class FutureResultClassifier
{
public:
	static void Classify(JsonValueWrapper& metadata, std::unique_ptr<IFutureResult>& outOffset);
};

