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
	mBinArm32A.name1 = obj["500368777"].asUInt();	 // Should be 0x8
	mBinArm32A.name2 = obj["1138065394"].asUInt();	 // Should be 0x8
	mBinArm32A.name3 = obj["1775762011"].asUInt();	 // Should be 0x8
	mBinArm32B.name1 = obj["538329334"].asUInt();	 // Should be 0x8
	mBinArm32B.name2 = obj["4195600013"].asUInt();	 // Should be 0x8
	mBinArm32B.name3 = obj["3557903396"].asUInt();	 // Should be 0x8
#endif

#if defined(ARM64)
	mBinArm64A.name1 = obj["462494170"].asUInt();	 // Should be 0x8
	mBinArm64A.name2 = obj["4119764849"].asUInt();	 // Should be 0x8
	mBinArm64A.name3 = obj["3482068232"].asUInt();	 // Should be 0x8
	mBinArm64B.name1 = obj["4287416125"].asUInt();	 // Should be 0x8
	mBinArm64B.name2 = obj["630145446"].asUInt();	 // Should be 0x8
	mBinArm64B.name3 = obj["1267842063"].asUInt();	 // Should be 0x8
#endif

	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
