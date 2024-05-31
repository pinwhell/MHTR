#pragma once

#include <IOffsetCalculator.h>

class IOffsetCalculatorProvider {
public:
	virtual ~IOffsetCalculatorProvider() {}
	virtual IOffsetCalculator* GetOffsetCalculator() = 0;
};