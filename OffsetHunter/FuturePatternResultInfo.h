#pragma once

#include "IFutureResultInfo.h"

class FuturePatternResultInfo : public IFutureResultInfo
{
private:
	std::string mPattern;
	size_t mDisk;
public:

	std::string getPattern();

	void ReportHppIncludes() override;

	std::string getCppDataType() override;
	std::string getCppDefaultRvalue() override;
};

