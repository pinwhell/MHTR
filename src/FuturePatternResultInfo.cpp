#include <OH/FuturePatternResultInfo.h>
#include <OH/TargetManager.h>

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
