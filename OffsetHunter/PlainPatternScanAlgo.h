#pragma once
#include "IOffsetScanAlgo.h"
#include <string>

class PlainPatternScanAlgo : public IOffsetScanAlgo
{
private:
	std::string mPattern;
public:
	bool Init() override;
	void IgniteScan() override;
};

