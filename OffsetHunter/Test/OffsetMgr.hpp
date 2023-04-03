#pragma once

#include <cstdint>

struct OffMgr {
#if defined(STATIC_OFFS)
#if defined(ARM32)
	struct BinArm32A {
		uintptr_t name3 = 0;
		uintptr_t name1 = 0;
		uintptr_t name2 = 0;
	} mBinArm32A;
	struct BinArm32B {
		uintptr_t name1 = 0;
		uintptr_t name2 = 0;
		uintptr_t name3 = 0;
	} mBinArm32B;
#endif

#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1 = 0;
		uintptr_t name2 = 0;
		uintptr_t name3 = 0;
	} mBinArm64A;
	struct BinArm64B {
		uintptr_t name1 = 0;
		uintptr_t name2 = 0;
		uintptr_t name3 = 0;
	} mBinArm64B;
#endif

#endif

} ;
extern OffMgr *gOffMgrOffs;
