#include "FuturePatternResultInfo.h"

#include "TargetManager.h"

std::string FuturePatternResultInfo::getPattern()
{
	return mPattern;
}

void FuturePatternResultInfo::ReportHppIncludes()
{
	mParent->getTargetManager()->AddInclude("string");
}

std::string FuturePatternResultInfo::getCppDataType()
{
	return "std::string";
}

std::string FuturePatternResultInfo::getCppDefaultRvalue()
{
	return "\"\"";
}
