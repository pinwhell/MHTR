#pragma once

#include "IFutureResultInfo.h"

class FutureOffsetResultInfo : public IFutureResultInfo {
protected:

	uint64_t mFinalOffset; // this denotes the Actual Result, if there is no offset it will contain ERR_INVALID_OFFSET
	uint64_t mFinalObfOffset; // this denotes the Actual Result obfuscated

public:

	FutureOffsetResultInfo();

	void setFinalOffset(uint64_t off);
	uint64_t getFinalOffset();
	uint64_t getFinalObfOffset();

	void ReportHppIncludes() override;
	void WriteHppStaticDeclsDefs() override;
	void WriteHppDynDecls() override;
	void WriteHppDynDefs() override;

	void OnParentTargetFinish() override;

	std::string getCppDataType() override;
	std::string getCppDefaultRvalue() override;
};


