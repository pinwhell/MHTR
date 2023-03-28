#include <cstdint>

struct OffMgr {
	#ifdef(STATIC_OFFS)

		#ifdef(ARM32)
			struct BinArm32A {
				uintptr_t name1 = 0x4; // This is a commnet!
				uintptr_t name2 = 0x4; // This is a commnet!
				uintptr_t name3 = 0x4; // This is a commnet!
			} mBinArm32A ;

			struct BinArm32B {
				uintptr_t name1 = 0x4; // This is a commnet!
				uintptr_t name2 = 0x4; // This is a commnet!
				uintptr_t name3 = 0x4; // This is a commnet!
			} mBinArm32B ;
		#endif

		#ifdef(ARM64)
			struct BinArm64A {
				uintptr_t name1 = 0x4; // This is a commnet!
				uintptr_t name2 = 0x4; // This is a commnet!
				uintptr_t name3 = 0x4; // This is a commnet!
			} mBinArm64A ;

			struct BinArm64B {
				uintptr_t name1 = 0x4; // This is a commnet!
				uintptr_t name2 = 0x4; // This is a commnet!
				uintptr_t name3 = 0x4; // This is a commnet!
			} mBinArm64B ;
		#endif

	#else

		#ifdef(ARM32)
			struct BinArm32A {
				uintptr_t name1; // This is a commnet!
				uintptr_t name2; // This is a commnet!
				uintptr_t name3; // This is a commnet!
			} mBinArm32A ;

			struct BinArm32B {
				uintptr_t name1; // This is a commnet!
				uintptr_t name2; // This is a commnet!
				uintptr_t name3; // This is a commnet!
			} mBinArm32B ;
		#endif

		#ifdef(ARM64)
			struct BinArm64A {
				uintptr_t name1; // This is a commnet!
				uintptr_t name2; // This is a commnet!
				uintptr_t name3; // This is a commnet!
			} mBinArm64A ;

			struct BinArm64B {
				uintptr_t name1; // This is a commnet!
				uintptr_t name2; // This is a commnet!
				uintptr_t name3; // This is a commnet!
			} mBinArm64B ;
		#endif
			
	#endif
};

extern OffMgr* g_Offs;