#pragma once
#include "ICapstoneHelper.h"

class Arm64CapstoneHelper : public ICapstoneHelper
{
public:
	Arm64CapstoneHelper();

	bool GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest) override;
	bool IsIntructionReturnRelated(cs_insn* pInst) override;
	bool IsIntructionPrologRelated(cs_insn* pInst) override;
	bool InstDisasmFollow(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outLocation) override;
	bool GetInstructionDisp(cs_insn* pInst, uintptr_t& outDisp) override;
	bool SolvePositionIndependentAddress(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) override;
	uint64_t getPcFromInstruction(cs_insn* inst) override;
};


