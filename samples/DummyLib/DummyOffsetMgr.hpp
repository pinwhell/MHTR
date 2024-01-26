#pragma once

#include <json/json.h>
#include <cstdint>

struct OffMgr {
#if defined(STATIC_OFFS)
#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1 = 0x8;	 // Should be 0x8 |_|Hi|_| 
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm64A;
#endif

#else

#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1;	 // Should be 0x8 |_|Hi|_| 
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm64A;
#endif

	void Set(const Json::Value& obj) {
#if defined(ARM64)
	mBinArm64A.name1 = obj["1353524362"].asUInt() ^ 2105391926;	 // Should be 0x8 |_|Hi|_| 
	mBinArm64A.name2 = obj["2417577301"].asUInt() ^ 4261248991;	 // Should be 0x8
	mBinArm64A.name3 = obj["3612997897"].asUInt() ^ 3609688011;	 // Should be 0x8
#endif

	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
