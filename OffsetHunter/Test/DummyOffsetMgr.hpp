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
	mBinArm32A.name1 = obj["981265668"].asUInt() ^ 1857613607;	 // Should be 0x8
	mBinArm32A.name2 = obj["391627288"].asUInt() ^ 4286264053;	 // Should be 0x8
	mBinArm32A.name3 = obj["2263146260"].asUInt() ^ 804209914;	 // Should be 0x8
	mBinArm32B.name1 = obj["4121648338"].asUInt() ^ 2109729720;	 // Should be 0x8
	mBinArm32B.name2 = obj["992780085"].asUInt() ^ 4164379989;	 // Should be 0x8
	mBinArm32B.name3 = obj["1212407290"].asUInt() ^ 2147417882;	 // Should be 0x8
#endif

#if defined(ARM64)
	mBinArm64A.name1 = obj["3879392179"].asUInt() ^ 2147180276;	 // Should be 0x8
	mBinArm64A.name2 = obj["2614164108"].asUInt() ^ 1325199350;	 // Should be 0x8
	mBinArm64A.name3 = obj["704061320"].asUInt() ^ 2067786965;	 // Should be 0x8
	mBinArm64B.name1 = obj["2898971163"].asUInt() ^ 3196762987;	 // Should be 0x8
	mBinArm64B.name2 = obj["2606030476"].asUInt() ^ 4276311093;	 // Should be 0x8
	mBinArm64B.name3 = obj["3691596715"].asUInt() ^ 1048504021;	 // Should be 0x8
#endif

	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
