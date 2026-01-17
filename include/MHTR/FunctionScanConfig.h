#pragma once

#include <MHTR/PatternScanConfig.h>
#include <CStone/IProvider.h>

namespace MHTR {

	struct FunctionScanConfig {
		PatternScanConfig mScanConfig;
		size_t mDefSize;
		ICapstoneProvider* mBranchCapstoneProvider;
		ICapstoneProvider* mFnCapstoneProvider;
	};

}