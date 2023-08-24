#pragma once
#include "ICapstoneHelper.h"
class Arm32CapstoneHelper : public ICapstoneHelper
{
public:
	Arm32CapstoneHelper();


	bool PCRelInstAddrRebaseRoot();

	bool GetInstructionDisp(cs_insn* pInst, uintptr_t& outDisp) override;
	bool SolvePositionIndependentAddress(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) override;
	bool GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest) override;
	bool IsIntructionReturnRelated(cs_insn* pInst) override;
	bool IsIntructionPrologRelated(cs_insn* pInst) override;
	uint64_t getPcFromInstruction(cs_insn* inst) override;
};

