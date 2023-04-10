#pragma once

#include <capstone/capstone.h>

class ICapstoneHelper
{
private:
	csh mHandle = 0x0;

	cs_arch mArch;
	cs_mode mMode;

protected:

	const unsigned char* mpBase;
	size_t mBaseSize;

public:
	ICapstoneHelper();
	virtual ~ICapstoneHelper();

	virtual bool Init();

	void setArch(cs_arch arch);
	void setMode(cs_mode mode);

	virtual bool PCRelInstAddrRebaseRoot() = 0;

	bool TryGetCallDestination(const unsigned char* pInst, uintptr_t& outDest);
	virtual bool GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest) = 0;
	virtual bool IsIntructionReturnRelated(cs_insn* pInst) = 0;
	virtual bool IsIntructionPrologRelated(cs_insn* pInst) = 0;

	bool TryInterpretDisp(const unsigned char* pInst, uintptr_t& outDisp);
	bool TryInterpretDispPCRelative(cs_insn* pInst, uintptr_t& outDisp);
	virtual bool InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp) = 0;
	virtual bool InterpretDispPCRelativeInst(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) = 0;

	bool TryComputeParagraphSize(const unsigned char* pInst, uintptr_t& outSize);

	void setBaseAddress(unsigned char* base);
	void setBaseSize(size_t sz);
};

