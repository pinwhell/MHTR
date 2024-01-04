#pragma once

#include "IJsonAccesor.h"
#include <memory>

class JsonAccesorClassifier
{
public:
	static bool Classify(const std::string& jsonLib, std::unique_ptr<IJsonAccesor>& outObj);
};

