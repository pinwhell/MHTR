#pragma once

#include <cstdint>
#include <json/json.h>

struct OffMgr {
#if defined(STATIC_OFFS)
#if defined(ARM32)
	struct BinArm32A {
		uintptr_t name1 = 0x8;	 // Should be 0x8
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm32A;
	struct BinArm32B {
		uintptr_t name1 = 0x8;	 // Should be 0x8
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm32B;
#endif

#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1 = 0x8;	 // Should be 0x8
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm64A;
	struct BinArm64B {
		uintptr_t name1 = 0x8;	 // Should be 0x8
		uintptr_t name2 = 0x8;	 // Should be 0x8
		uintptr_t name3 = 0x8;	 // Should be 0x8
	} mBinArm64B;
#endif

#else

#if defined(ARM32)
	struct BinArm32A {
		uintptr_t name1;	 // Should be 0x8
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm32A;
	struct BinArm32B {
		uintptr_t name1;	 // Should be 0x8
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm32B;
#endif

#if defined(ARM64)
	struct BinArm64A {
		uintptr_t name1;	 // Should be 0x8
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm64A;
	struct BinArm64B {
		uintptr_t name1;	 // Should be 0x8
		uintptr_t name2;	 // Should be 0x8
		uintptr_t name3;	 // Should be 0x8
	} mBinArm64B;
#endif

	void Set(const Json::Value& obj) {
#if defined(ARM32)
	mBinArm32A.name1 = obj["1613443683"].asUInt() ^ 1985833994;	 // Should be 0x8
	mBinArm32A.name2 = obj["2135897944"].asUInt() ^ 1610241857;	 // Should be 0x8
	mBinArm32A.name3 = obj["4125678665"].asUInt() ^ 3214868459;	 // Should be 0x8
	mBinArm32B.name1 = obj["1558618447"].asUInt() ^ 2130704125;	 // Should be 0x8
	mBinArm32B.name2 = obj["133037476"].asUInt() ^ 2608821920;	 // Should be 0x8
	mBinArm32B.name3 = obj["3426461397"].asUInt() ^ 2142748451;	 // Should be 0x8
#endif

#if defined(ARM64)
	mBinArm64A.name1 = obj["1353524362"].asUInt() ^ 2105391926;	 // Should be 0x8
	mBinArm64A.name2 = obj["2417577301"].asUInt() ^ 4261248991;	 // Should be 0x8
	mBinArm64A.name3 = obj["3612997897"].asUInt() ^ 3609688011;	 // Should be 0x8
	mBinArm64B.name1 = obj["2913580123"].asUInt() ^ 257130281;	 // Should be 0x8
	mBinArm64B.name2 = obj["315769873"].asUInt() ^ 4134368048;	 // Should be 0x8
	mBinArm64B.name3 = obj["4130067440"].asUInt() ^ 4287559064;	 // Should be 0x8
#endif

	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
