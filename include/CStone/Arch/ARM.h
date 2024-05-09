#pragma once

#include <CStone/CStone.h>
#include <CStone/Utility.h>

class ARM32CapstoneUtility : public ICapstoneUtility {
public:
    bool InsnHasRegister(const cs_insn* pIns, uint16_t reg) const override;
    uint64_t InsnGetImmByIndex(const cs_insn* pIns, size_t index) const override;
    uint16_t InsnGetPseudoDestReg(const cs_insn* pIns) const override;
    bool InsnIsBranch(const cs_insn* pInsn) const override;
    bool InsnHasCondition(const cs_insn* pInsn) const override;

    CapstoneUtility mBaseUtility;
};

class ARM32CapstoneHeuristic : public ICapstoneHeuristic {
public:
    bool InsnIsProcedureEntry(const cs_insn* pInsn) const override;
    bool InsnIsProcedureExit(const cs_insn* pInsn) const override;
};

class ARM32Capstone : public ICapstone {
public:
    ARM32Capstone(bool mbThumb = false, bool bDetailedInsn = true);

    ICapstoneUtility* getUtility() override;
    ICapstoneHeuristic* getHeuristic() override;
    CapstoneDismHandle Disassemble(const void* start, size_t nBytes, uint64_t pcAddr = 0) override;
    CsInsn DisassembleOne(const void* start, uint64_t pcAddr = 0) override;
    void InsnForEach(const void* start, std::function<bool(const CsInsn& insn)> callback, uint64_t pcAddr = 0, size_t buffSize = SIZE_MAX) override;

    Capstone mCapstone;
    ARM32CapstoneUtility mUtility;
    ARM32CapstoneHeuristic mHeuristic;
};

template<typename ResultT, typename T>
ResultT ARM32PCCompute(ICapstone* capstone, T at, uint64_t disp = 0)
{
    auto dism = capstone->Disassemble((char*)at, 4 * 2, (uint64_t)at);

    if (dism.mCount < 2)
        throw std::runtime_error(fmt::format("PC Follow {}: 2 instrunction disassembly failed", fmt::ptr((char*)at)));

    return  (ResultT)((char*)at + disp + (dism.mpFirst[0].size + dism.mpFirst[1].size));
}

template<typename ResultT, typename T>
ResultT ARM32LDRPCDispResolve(ICapstone* capstone, T at, bool bDerref = false)
{
    const void* _at = (const void*)at;

    CsInsn insn = capstone->DisassembleOne(_at);

    if (insn->id != ARM_INS_LDR)
        throw std::runtime_error(fmt::format("LEAPCDisp Follow '{} {}': unexpected instruction", insn->mnemonic, insn->op_str));

    auto& memOp = insn->detail->arm.operands[1];

    if (memOp.type != CS_OP_MEM ||
        memOp.mem.index != ARM_REG_INVALID)
        throw std::runtime_error(fmt::format("LEAPCDisp Follow '{} {}': unexpected instruction format", insn->mnemonic, insn->op_str));

    uint64_t dstAddr = ARM32PCCompute<uint64_t>(capstone, at, memOp.mem.disp);

    if (bDerref)
        return (ResultT)(*(uint32_t*)dstAddr);

    return (ResultT)(dstAddr);
}

template<typename ResultT, typename T>
ResultT ARM32FarPcRelLEATryResolve(ICapstone* capstone, T at, bool bDerref = false)
{
    uint32_t pcRelDisp = ARM32LDRPCDispResolve<uint32_t>(capstone, at, true);
    CsInsn ldrInsn = capstone->DisassembleOne((const void*)at);
    ICapstoneUtility* utility = capstone->getUtility();
    auto Rd = utility->InsnGetPseudoDestReg(&ldrInsn.mInsn);
    bool bFound = false;
    ResultT res{};
    const void* nextInsnStart = (const char*)at + ldrInsn->size;

    capstone->InsnForEach(nextInsnStart, [&](const CsInsn& insn) {
        if (!utility->InsnHasRegister(&insn.mInsn, Rd))
            return true;

        if (!utility->InsnHasRegister(&insn.mInsn, ARM_REG_PC))
            return true;

        const void* dstAddr = ARM32PCCompute<const void*>(capstone, insn->address, pcRelDisp);

        res = bDerref ? (ResultT)(const void*)(*(uint32_t*)dstAddr) : (ResultT)dstAddr;

        return !(bFound = true);
        }, (uint64_t)nextInsnStart);

    if (!bFound)
        throw std::runtime_error(fmt::format("'{} {}' not found finalizer", ldrInsn->mnemonic, ldrInsn->op_str));

    return res;
}