#pragma once

#include <capstone/capstone.h>
#include <functional>

class ICapstoneHelper
{
private:
	csh mHandle = 0x0;

	cs_arch mArch;
	cs_mode mMode;

protected:

	union {
		const unsigned char* mpBase;
		uintptr_t mBase;
	};

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

	bool InstDisasmTryGetDisp(const unsigned char* pInst, uintptr_t& outDisp);
	virtual bool GetInstructionDisp(cs_insn* pInst, uintptr_t& outDisp) = 0;
	bool DisasmTrySolvePositionIndependentAddress(cs_insn* pInst, uintptr_t& outDisp);
	virtual bool SolvePositionIndependentAddress(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) = 0;

	virtual uint64_t getPcFromInstruction(cs_insn* inst) = 0;

	bool TryComputeParagraphSize(const unsigned char* pInst, uintptr_t& outSize);

	void setBaseAddress(unsigned char* base);
	void setBaseSize(size_t sz);

	void ForEachInstructionAbs(const unsigned char* startAt, std::function<bool(cs_insn* pInst)> callback);
	void ForEachInstructionRel(uint64_t baseOffset, std::function<bool(cs_insn* pInst)> callback);
};

