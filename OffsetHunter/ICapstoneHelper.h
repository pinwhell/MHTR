#pragma once

#include <capstone/capstone.h>

class ICapstoneHelper
{
private:
	csh mHandle;

	cs_arch mArch;
	cs_mode mMode;

protected:

	const unsigned char* mpBase;

public:
	ICapstoneHelper();

	virtual bool Init();

	void setArch(cs_arch arch);
	void setMode(cs_mode mode);

	virtual bool PCRelInstAddrRebaseRoot() = 0;

	bool TryInterpretDisp(const unsigned char* pInst, uintptr_t& outDisp);
	bool TryInterpretDispPCRelative(cs_insn* pInst, uintptr_t& outDisp);
	virtual bool InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp) = 0;
	virtual bool InterpretDispPCRelativeInst(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) = 0;

	void setBaseAddress(unsigned char* base);
};

