#pragma once

#include <MHTR/IOffsetCalculator.h>

namespace MHTR {
	class IOffsetCalculatorProvider {
	public:
		virtual ~IOffsetCalculatorProvider() {}
		virtual IOffsetCalculator* GetOffsetCalculator() = 0;
	};
}