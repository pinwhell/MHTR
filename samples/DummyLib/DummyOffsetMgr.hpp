#pragma once

#include <json/json.h>
#include <cstdint>

struct OffMgr {
#if defined(STATIC_OFFS)
#if defined(ARM32)
	struct BinArm32A {
		uintptr_t name1 = 0x8;	 // Should be 0x8 #(Hi)#
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm32A;
#endif

#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1 = 0x8;	 // Should be 0x8 #(Hi)#
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm64A;
#endif

#else

#if defined(ARM32)
	struct BinArm32A {
		uintptr_t name1;	 // Should be 0x8 #(Hi)#
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm32A;
#endif

#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1;	 // Should be 0x8 #(Hi)#
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm64A;
#endif

	void Set(const Json::Value& obj) {
		static bool initialized = false;

		if(initialized) return;

#if defined(ARM32)
		mBinArm32A.name1 = obj["500368777"].asUInt() ^ 4023873318;	 // Should be 0x8 #(Hi)#
		mBinArm32A.name2 = obj["1138065394"].asUInt() ^ 1844445062;	 // Should be 0x8
		mBinArm32A.name3 = obj["1775762011"].asUInt() ^ 4127170522;	 // Should be 0x8
#endif

#if defined(ARM64)
		mBinArm64A.name1 = obj["462494170"].asUInt() ^ 4000739487;	 // Should be 0x8 #(Hi)#
		mBinArm64A.name2 = obj["4119764849"].asUInt() ^ 3581899242;	 // Should be 0x8
		mBinArm64A.name3 = obj["3482068232"].asUInt() ^ 1333386720;	 // Should be 0x8
#endif

		initialized = true;
	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
