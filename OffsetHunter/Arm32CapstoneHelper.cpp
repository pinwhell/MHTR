#include "Arm32CapstoneHelper.h"
#include "CapstoneAux.h"

Arm32CapstoneHelper::Arm32CapstoneHelper()
{
	setArch(CS_ARCH_ARM);
	setMode(CS_MODE_ARM);
}

bool Arm32CapstoneHelper::PCRelInstAddrRebaseRoot()
{
	return false;
}

bool Arm32CapstoneHelper::InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp)
{
    switch (pInst->id)
    {

    case ARM_INS_LDR:
    case ARM_INS_LDRH:
    case ARM_INS_LDRD:
    case ARM_INS_LDRB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDREXB:
    {
        if (ArmCapstoneAux::GetRValueRegType(pInst) == ARM_REG_PC) return TryInterpretDispPCRelative(pInst, outDisp);
        else outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_STR:
    case ARM_INS_STRH:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STREXB:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_VLDR:
    case ARM_INS_VSTR:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_ADD:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].imm;
    }break;

    case ARM_INS_MOV:
    case ARM_INS_MOVW:
    case ARM_INS_MOVT:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = op.imm;
            break;
        }
    }

    case ARM_INS_MVN:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = ~(op.imm);
            break;
        }
    }

    default:
        return false;
    }

    return true;
}

bool Arm32CapstoneHelper::InterpretDispPCRelativeInst(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outDisp)
{
    uint16_t regPcRelOffHolderType = ArmCapstoneAux::GetLValueRegType(pInstBegin);
    uintptr_t targetPcRelOff = ArmCapstoneAux::ResolvePCRelative((unsigned char*)pInstBegin->address, pInstBegin->detail->arm.operands[pInstBegin->detail->arm.op_count - 1].mem.disp);

    for (auto* pCurrInst = pInstBegin + 1; pCurrInst < pInstEnd; pCurrInst++)
    {

        switch (pCurrInst->id) {

        case ARM_INS_LDR:
        case ARM_INS_STR:
        {
            if (pCurrInst->detail->arm.operands[1].mem.base == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[1].mem.index == regPcRelOffHolderType)
            {
                outDisp = (uintptr_t(pCurrInst->address) + 0x8 + targetPcRelOff) - uintptr_t(mpBase);

                return true;
            }
        }break;

        case ARM_INS_ADD:
        {
            if ((pCurrInst->detail->arm.operands[1].reg == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[2].reg == regPcRelOffHolderType) ||
                (pCurrInst->detail->arm.operands[2].reg == ARM_REG_PC &&
                    pCurrInst->detail->arm.operands[1].reg == regPcRelOffHolderType))
            {
                outDisp = (uintptr_t(pCurrInst->address) + 0x8 + targetPcRelOff) - uintptr_t(mpBase);

                return true;
            }
        }break;

        }
    }

    return false;
}

bool Arm32CapstoneHelper::GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest)
{
    switch (pInst->id)
    {
    case ARM_INS_BL:
    case ARM_INS_B:
    {
        outDest = pInst->detail->arm.operands[0].imm;
        return true;
    }

    }
    return pInst->address;

    return false;
}

bool Arm32CapstoneHelper::IsIntructionReturnRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicReturn(pInst);
}

bool Arm32CapstoneHelper::IsIntructionPrologRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicProlog(pInst);
}
